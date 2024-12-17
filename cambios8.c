#include <ncurses.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#define MAX_PACKETS 1000
#define RAW_DATA_LENGTH 256
    WINDOW *win;
    WINDOW *won;
    WINDOW *wor;

int cont = 0;
int mostp = 0;
int mostpp;
int link_hdr_length = 0;
int packet_count = 0;
char filter_string[256] = "host www.duckduckgo.com";  // Filtro por defecto

// Estructura para almacenar los datos de los paquetes
struct packet_data {
    int no;
    char protocol[10];
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int length;
    u_char raw_data[RAW_DATA_LENGTH];
    long timestamp_ms;  // Timestamp en milisegundos
};

// Array de paquetes capturados
struct packet_data packets[MAX_PACKETS];

long capture_start_time_ms = 0;  // Para almacenar el inicio de la captura

void print_table_header() {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
    scrollok(won, TRUE);
    idlok(won, TRUE);
    mvwprintw(won, 1, 1, "No. | Time      | Protocol | Src IP          | Dst IP          | Length");
    mvwprintw(won, 2, 1, "------------------------------------------------------------------------");
    wrefresh(won);
}

void print_table_headers() {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
    scrollok(win, TRUE);
    idlok(win, TRUE);
    mvwprintw(won, 1, 1, "No. | Time      | Protocol | Src IP          | Dst IP          | Length");
    mvwprintw(won, 2, 1, "------------------------------------------------------------------------");
    wrefresh(won);
}

void print_packet_info(int packet_no, long timestamp_ms, const char *protocol, const char *src_ip, const char *dst_ip, int length) {
    long seconds = timestamp_ms / 1000;  // Obtener los segundos
    long milliseconds = timestamp_ms % 1000;  // Obtener los milisegundos restantes
    if(packet_no < 18){
        wattron(won, COLOR_PAIR(4));
        mvwprintw(won, packet_no + 2, 1, "%-4d| %ld.%03ld     | %-8s| %-15s | %-15s| %-6d", packet_no, seconds, milliseconds, protocol,src_ip,dst_ip,length);
        scrollok(won, TRUE);
        wattroff(won, COLOR_PAIR(4));
        wrefresh(won);           
    }
    if(packet_no % 18 == 0){
        wclear(won);
        cont = 3;
        initscr();
        cbreak();
        noecho();
        curs_set(0);
        keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
        won = newwin(22, 80, 0, 0); //Ventana de 20x150 en la posicion (0,0)
        scrollok(win, TRUE);
        idlok(won, TRUE);
        box(won, 0, 0);
        mvwprintw(won, 1, 1, "No. | Time      | Protocol | Src IP          | Dst IP          | Length");
        mvwprintw(won, 2, 1, "------------------------------------------------------------------------");
        wrefresh(won);    
    }
    if(packet_no >= 18){
        wattron(won, COLOR_PAIR(4));
        mvwprintw(won, cont, 1, "%-4d| %ld.%03ld     | %-8s| %-15s | %-15s| %-6d", packet_no, seconds, milliseconds, protocol, src_ip,dst_ip,length);
        wrefresh(won);
        wattroff(won, COLOR_PAIR(4));
        cont++;    
    }
}

void print_packet_infos(int packet_no, long timestamp_ms, const char *protocol, const char *src_ip, const char *dst_ip, int length) {
    long seconds = timestamp_ms / 1000;  // Obtener los segundos
    long milliseconds = timestamp_ms % 1000;  // Obtener los milisegundos restantes
    if(packet_no % 18 == 0){
        mostp = wgetch(win);
        wclear(won);
        cont = 3;
        initscr();
        cbreak();
        noecho();
        start_color();
        curs_set(0);
        keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
        won = newwin(22, 80, 0, 0); //Ventana de 20x150 en la posicion (0,0)
        box(won, 0, 0);
        mvwprintw(won, 1, 1, "No. | Time      | Protocol | Src IP          | Dst IP          | Length");
        mvwprintw(won, 2, 1, "------------------------------------------------------------------------");
        wrefresh(won);    
    }
    if(packet_no >= 18 && mostp == 'd' | mostp == 'D'){
        wattron(won, COLOR_PAIR(4));
        mvwprintw(won, cont, 1, "%-4d| %ld.%03ld     | %-8s| %-15s | %-15s| %-6d", packet_no, seconds, milliseconds, protocol, src_ip,dst_ip,length);
        wattroff(won, COLOR_PAIR(4));
        wrefresh(won);
        cont++;
    }    
    if(packet_no < 18){
        wattron(won, COLOR_PAIR(4));
        mvwprintw(won, packet_no + 2, 1, "%-4d| %ld.%03ld     | %-8s| %-15s | %-15s| %-6d", packet_no, seconds, milliseconds, protocol,src_ip,dst_ip,length);
        scrollok(won, TRUE);
        wattroff(won, COLOR_PAIR(4));
        wrefresh(won);           
    }
}



void print_raw_data(const uint8_t *data, int length) {
    // Inicializa ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE); // Habilitar teclas especiales
    win = newwin(10, 40, 0, 80); //Ventana de 30x10 en la posicion (0,0)
    box(win, 0, 0);
    mvwprintw(win, 1, 1, "Presione cualquier tecla");
    mvwprintw(win, 2, 1, "para regresar al menu");
    wrefresh(win);

    // Título de la ventana
    mvwprintw(wor, 1, 1, "Raw Data (Hex + ASCII):");

    int row = 2;  // Inicia en la segunda fila (después del título)
    int col = 1;  // Columna inicial

    // Iterar sobre los datos en bloques de 16 bytes
    for (int i = 0; i < length; i++) {
        if (i % 16 == 0) {
            // Nueva línea para cada bloque de 16 bytes
            row++;
            col = 1;

            // Dirección base en formato hexadecimal
            mvwprintw(wor, row, col, "%04x: ", i);  // Dirección base
        }

        // Imprimir el byte en formato hexadecimal
        mvwprintw(wor, row, col + 6 + (i % 16) * 3, "%02x ", data[i]);

        // Cuando llegamos al final de una línea (16 bytes) o al final de los datos
        if (i % 16 == 15 || i == length - 1) {
            // Alinear la columna del ASCII a la derecha del bloque hexadecimal
            int ascii_col = col + 6 + 16 * 3 + 2;  // Ajuste para la columna de ASCII

            // Rellenar los espacios faltantes en el bloque hexadecimal si no se completa la línea
            if (i % 16 != 15) {
                int padding = 16 - (i % 16) - 1;  // Cantidad de espacios vacíos a agregar
                for (int j = 0; j < padding; j++) {
                    mvwprintw(wor, row, col + 6 + (i % 16 + j + 1) * 3, "   ");  // Espacios de relleno
                }
            }

            // Imprimir los caracteres ASCII correspondientes
            for (int j = i - (i % 16); j <= i; j++) {
                mvwprintw(wor, row, ascii_col + (j - (i - (i % 16))), "%c",
                    (data[j] >= 32 && data[j] <= 126) ? data[j] : '.');
            }
        }

        // Después de cada byte en hexadecimal, nos movemos 3 columnas
        if (i % 16 != 15) {
            col += 3;  // Espaciado de los bytes en hexadecimal
        }
    }

    // Refrescar la ventana para mostrar la salida
    wrefresh(wor);

    // Espera una tecla para finalizar
    wgetch(wor);

}




// Función para mostrar los datos "raw" en formato hexadecimal y ASCII
/*void print_raw_data(const u_char *data, int length) {
    printf("\nRaw Data (Hex + ASCII):\n");
    for (int i = 0; i < length; i++) {
        if (i % 16 == 0)
            printf("\n%04x: ", i);  // Dirección base para cada línea
        printf("%02x ", data[i]);  // Imprime el byte en formato hexadecimal

        // Cuando llegamos al final de una línea (16 bytes) o al final de los datos
        if (i % 16 == 15 || i == length - 1) {
            // Añadir relleno para alinear la columna de ASCII si no estamos en una línea completa
            if (i % 16 != 15) {
                int padding = 16 - (i % 16) - 1;
                for (int j = 0; j < padding; j++) {
                    printf("   ");  // Espacios de relleno
                }
            }
            printf(" ");
            // Imprimir caracteres ASCII correspondientes
            for (int j = i - (i % 16); j <= i; j++) {
                printf("%c", data[j] >= 32 && data[j] <= 126 ? data[j] : '.');
            }
        }
    }
    printf("\n");
}*/

// Función de callback para capturar los paquetes
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr) {
    packetd_ptr += link_hdr_length;
    struct ip *ip_hdr = (struct ip *)packetd_ptr;

    char packet_srcip[INET_ADDRSTRLEN];
    char packet_dstip[INET_ADDRSTRLEN];
    strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src));
    strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst));
    int packet_len = ntohs(ip_hdr->ip_len);

    // Determinar el protocolo
    char protocol[10];
    switch (ip_hdr->ip_p) {
        case IPPROTO_TCP: strcpy(protocol, "TCP"); break;
        case IPPROTO_UDP: strcpy(protocol, "UDP"); break;
        case IPPROTO_ICMP: strcpy(protocol, "ICMP"); break;
        default: strcpy(protocol, "UNKNOWN"); break;
    }

    // Calcular el tiempo en milisegundos
    long timestamp_ms = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;
    
    // Inicializar el tiempo de inicio si es la primera captura
    if (packet_count == 0) {
        capture_start_time_ms = timestamp_ms;
    }

    // Calcula el tiempo desde el inicio de la captura
    timestamp_ms -= capture_start_time_ms;

    // Almacenar los datos del paquete en la estructura
    if (packet_count < MAX_PACKETS) {
        packets[packet_count].no = packet_count + 1;
        strcpy(packets[packet_count].protocol, protocol);
        strcpy(packets[packet_count].src_ip, packet_srcip);
        strcpy(packets[packet_count].dst_ip, packet_dstip);
        packets[packet_count].length = packet_len;
        packets[packet_count].timestamp_ms = timestamp_ms;  // Guardar el tiempo en milisegundos

        // Copiar los datos "raw" del paquete
        memcpy(packets[packet_count].raw_data, packetd_ptr, pkthdr->len < RAW_DATA_LENGTH ? pkthdr->len : RAW_DATA_LENGTH);

        // Imprimir el paquete en tiempo real
        print_packet_info(packets[packet_count].no, packets[packet_count].timestamp_ms,
                           packets[packet_count].protocol, packets[packet_count].src_ip, 
                           packets[packet_count].dst_ip, packets[packet_count].length);

        packet_count++;
    }
}

// Función para consultar los paquetes capturados
void show_packets() {
    mostpp = 0;
    print_table_headers();
    while (mostpp <= packet_count){
        print_packet_infos(packets[mostpp].no, packets[mostpp].timestamp_ms, packets[mostpp].protocol,
                           packets[mostpp].src_ip, packets[mostpp].dst_ip, packets[mostpp].length);
        mostpp++;
    }
    wclear(win);
    wrefresh(win);
}

// Muestra los detalles de un paquete específico
void show_packet_details() {
    werase(win);
    initscr();
    echo();
    keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
    win = newwin(10, 50, 0, 80);
    box(win, 0, 0);
    wattron(win, COLOR_PAIR(2));
    mvwprintw(win, 1,1, "Ingrese el numero                              ");
    mvwprintw(win, 2,1, "del paquete a consultar:                       ");
    wrefresh(win);
    int num = 0;
    mvwscanw(win, 2, 26, "%d", &num);
    wattroff(win, COLOR_PAIR(2));
    wrefresh(win);
    if (num < 1 || num > packet_count) {
        wattron(win, COLOR_PAIR(2));
        mvwprintw(win, 3,1, "Numero invalido                                ");
        wattroff(win, COLOR_PAIR(2));
        wgetch(win);
        werase(win);
        wrefresh(win);
        return;
    }

    werase(win);
    wrefresh(win);
    struct packet_data *ps = &packets[num - 1];

    // Mostrar los datos "raw" del paquete
    print_raw_data(ps->raw_data, ps->length);
}

// Función para exportar los datos capturados a un archivo CSV
void export_data_csv(const char *filename) {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
    win = newwin(10, 43, 0, 80); //Ventana de 30x10 en la posicion (0,0)
    box(win, 0, 0);
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        mvwprintw(win, 1, 1, "Error al abrir el archivo para exportar datos.");
        wgetch(win);
        werase(win);
        wrefresh(win);
        return;
    }

    // Escribir encabezado del archivo CSV
    fprintf(file, "No.,Time (s.ms),Protocol,Source IP,Destination IP,Length\n");

    // Escribir los datos de cada paquete
    for (int i = 0; i < packet_count; i++) {
        long seconds = packets[i].timestamp_ms / 1000;
        long milliseconds = packets[i].timestamp_ms % 1000;
        fprintf(file, "%d,%ld.%03ld,%s,%s,%s,%d\n",
                packets[i].no,
                seconds,
                milliseconds,
                packets[i].protocol,
                packets[i].src_ip,
                packets[i].dst_ip,
                packets[i].length);
    }

    fclose(file);
    mvwprintw(win, 1, 1, "Datos exportados en formato CSV a %s", filename);
    wgetch(win);
    werase(win);
    wrefresh(win);
}

// Función para leer teclas sin bloqueo
int kbhit(void) {
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);    // Desactivar entrada canonica y echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);   // No bloquear
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, 0);    // Volver a la configuración normal
    return (ch != EOF) ? ch : -1;
}

void set_filter_src_ip(const char *src_ip) {
       
    snprintf(filter_string, sizeof(filter_string), "src host %s", src_ip);
   
    
}

void set_filter_dst_ip(const char *dst_ip) {
    
    snprintf(filter_string, sizeof(filter_string), "dst host %s", dst_ip);
    
}

// Establecer filtro por puerto de origen
void set_filter_src_port(int src_port) {
    
    snprintf(filter_string, sizeof(filter_string), "src port %d", src_port);
    
}

// Establecer filtro por puerto de destino
void set_filter_dst_port(int dst_port) {
    
    snprintf(filter_string, sizeof(filter_string), "dst port %d", dst_port);
    
}

// Establecer filtro por protocolo (TCP, UDP, ICMP, etc.)
void set_filter_protocol(const char *protocol) {
    
    snprintf(filter_string, sizeof(filter_string), "%s", protocol);
    
}

// Aplicar filtro de captura
void apply_filter(pcap_t *dev, struct bpf_program *bpf, bpf_u_int32 netmask) {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    start_color();
    keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
    win = newwin(10, 60, 0, 80); //Ventana de 30x10 en la posicion (0,0)
    box(win, 0, 0);
    if (pcap_compile(dev, bpf, filter_string, 0, netmask) == PCAP_ERROR) {
        mvwprintw(win, 1, 1, "Error al compilar el filtro: %s", pcap_geterr(dev));
    } else if (pcap_setfilter(dev, bpf) != 0) {
        mvwprintw(win, 1, 1, "Error al establecer el filtro: %s", pcap_geterr(dev));
    } else {
        mvwprintw(win, 1, 1, "Filtro aplicado correctamente.");
    }
    wgetch(win);
    werase(win);
    wrefresh(win);
}

int menu(){
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    start_color();
    keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
    win = newwin(10, 40, 0, 80); //Ventana de 30x10 en la posicion (0,0)
    box(win, 0, 0);
    won = newwin(22, 80, 0, 0); //Ventana de 20x150 en la posicion (0,0)
    box(won, 0, 0);
    print_table_header();
    wrefresh(won);
    wor = newwin(12, 130, 22, 0);
    box(wor, 0, 0);
    wrefresh(wor);
    init_pair(1, COLOR_RED, COLOR_WHITE);
    init_pair(4, COLOR_WHITE, COLOR_BLUE);
    wattron(win, COLOR_PAIR(1));
    mvwprintw(win, 1, 1, "-----------------MENU-----------------");
    wattroff(win, COLOR_PAIR(1));
    init_pair(2, COLOR_BLACK, COLOR_WHITE);
    wattron(win, COLOR_PAIR(2));
    mvwprintw(win, 2, 1, "1. Iniciar captura de paquetes        ");
    mvwprintw(win, 3, 1, "2. Consultar paquetes capturados      ");
    mvwprintw(win, 4, 1, "3. Consultar detalles de un paquete   ");
    mvwprintw(win, 5, 1, "4. Establecer filtro de captura       ");
    mvwprintw(win, 6, 1, "5. Exportar datos a un archivo        ");
    mvwprintw(win, 7, 1, "6. Salir                              ");
    mvwprintw(win, 8, 1, "                                      ");
    wattroff(win, COLOR_PAIR(2));
    wrefresh(win);
    int opc = wgetch(win);
    werase(win);
    wrefresh(win);
    return opc;
}

int main(int argc, char const *argv[]) {
    char *device = "enp0s3";  // Cambiar al dispositivo adecuado
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *dev = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);
    if (dev == NULL) {
        printf("ERR: pcap_open_live() %s\n", error_buffer);
        exit(1);
    }

    struct bpf_program bpf;
    bpf_u_int32 netmask;

    // Aplicar el filtro inicial
    if (pcap_compile(dev, &bpf, filter_string, 0, netmask) == PCAP_ERROR) {
        printf("ERR: pcap_compile() %s", pcap_geterr(dev));
    }

    if (pcap_setfilter(dev, &bpf)) {
        printf("ERR: pcap_setfilter() %s", pcap_geterr(dev));
    }

    int link_hdr_type = pcap_datalink(dev);
    switch (link_hdr_type) {
        case DLT_NULL: link_hdr_length = 4; break;
        case DLT_EN10MB: link_hdr_length = 14; break;
        default: link_hdr_length = 0;
    }

    while (1) {
        

        int choice = menu();
        int packet_number;
        char filename[256];

        switch (choice) {
            case '1':
                initscr();
                cbreak();
                noecho();
                curs_set(0);
                keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
                win = newwin(10, 40, 0, 80); //Ventana de 30x10 en la posicion (0,0)
                box(win, 0, 0);
                wattron(win, COLOR_PAIR(1));
                mvwprintw(win, 1, 1, "Precione la tecla -> 'q'              ");
                mvwprintw(win, 2, 1, "Para detener la captura               ");
                wattroff(win, COLOR_PAIR(1));
                wrefresh(win);
                packet_count = 0;  // Resetear el contador de paquetes
                print_table_header();

                // Captura hasta que se presione la tecla
                while (1) {
                    struct pcap_pkthdr header;
                    const u_char *packet = pcap_next(dev, &header);
                    if (packet) {
                        call_me(NULL, &header, packet);
                    }
                        int tecla;
                        nodelay(win, TRUE);
                        if ((tecla = wgetch(win)) == 'q'){
                            werase(win);
                            wrefresh(win);
                            break;
                        }
                }
                break;

            case '2':
                initscr();
                cbreak();
                noecho();
                curs_set(0);
                keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
                win = newwin(10, 40, 0, 80); //Ventana de 30x10 en la posicion (0,0)
                box(win, 0, 0);
                init_pair(3, COLOR_BLUE, COLOR_WHITE);
                wattron(win, COLOR_PAIR(3));
                mvwprintw(win, 1, 1, "Para avanzar:                         ");
                mvwprintw(win, 2, 1, "Precione la tecla -> 'd'              ");
                wattroff(win, COLOR_PAIR(3));
                wrefresh(win);
                show_packets();
                break;

            case '3':
                show_packet_details();
                break;

            case '4':
                initscr();
                cbreak();
                noecho();
                curs_set(0);
                keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
                win = newwin(10, 43, 0, 80); //Ventana de 30x10 en la posicion (0,0)
                box(win, 0, 0);
                wattron(win, COLOR_PAIR(1));
                mvwprintw(win, 1, 1, "------------------MENU-------------------");
                wattroff(win, COLOR_PAIR(1));
                init_pair(2, COLOR_BLACK, COLOR_WHITE);
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, 2, 1, "1. Establecer filtro por IP de origen    ");
                mvwprintw(win, 3, 1, "2. Establecer filtro por IP de destino   ");
                mvwprintw(win, 4, 1, "3. Establecer fitro por puerto de origen ");
                mvwprintw(win, 5, 1, "4. Establecer filtro por puerto destino  ");
                mvwprintw(win, 6, 1, "5. Establecer fitro por protocolo        ");
                mvwprintw(win, 7, 1, "6. Salir                                 ");
                wattroff(win, COLOR_PAIR(2));
                wrefresh(win);
                
                int filter_choice = wgetch(win);


    switch (filter_choice) {
        case '1':
            {
                echo();
                char src_ip[16];  // Almacenará la IP de origen
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, 8, 1, "Ingrese la IP de origen:                 ");
                mvwscanw(win, 8, 26, "%s", src_ip);
                wattroff(win, COLOR_PAIR(2));
                werase(win);
                wrefresh(win);
                set_filter_src_ip(src_ip);  // Llamada a la función para establecer el filtro
                apply_filter(dev, &bpf, netmask);  // Aplicar filtro
                werase(win);
                
        break;
            }
        case '2':
            {
                echo();
                char dst_ip[16];  // Almacenará la IP de destino
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, 8, 1, "Ingrese la IP de destino:                ");
                mvwscanw(win, 8, 27, "%s", dst_ip);
                wattroff(win, COLOR_PAIR(2));
                werase(win);
                wrefresh(win);
                set_filter_dst_ip(dst_ip);  // Llamada a la función para establecer el filtro
                apply_filter(dev, &bpf, netmask);  // Aplicar filtro
            break;
            }


        case '3':
            {
                echo();
                int src_port;
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, 8, 1, "Ingrese el puerto de origen:             ");
                mvwscanw(win, 8, 29, "%d", &src_port);
                wattroff(win, COLOR_PAIR(2));
                werase(win);
                wrefresh(win);
                set_filter_src_port(src_port);  // Llamada a la función para establecer el filtro
                apply_filter(dev, &bpf, netmask);  // Aplicar filtro
            break;
            }


        case '4':
            {
                echo();
                int dst_port;
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, 8, 1, "Ingrese el puerto de destino:            ");
                mvwscanw(win, 8, 30, "%d", &dst_port);
                wattroff(win, COLOR_PAIR(2));
                werase(win);
                wrefresh(win);
                set_filter_dst_port(dst_port);  // Llamada a la función para establecer el filtro
                apply_filter(dev, &bpf, netmask);  // Aplicar filtro
            break;
            }


        case '5':
            {
                echo();
                char protocol[10];  // Almacena el protocolo
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, 8, 1, "Ingrese el protocolo (minusculas):       ");
                mvwscanw(win, 8, 35, "%s", protocol);
                wattroff(win, COLOR_PAIR(2));
                werase(win);
                wrefresh(win);
                set_filter_protocol(protocol);  // Llamada a la función para establecer el filtro
                apply_filter(dev, &bpf, netmask);  // Aplicar filtro
            break;
            }


        case '6':{
            // Volver al menú principal, solo salimos del submenu de filtros
                werase(win);
                wrefresh(win);
            break;

        default:
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, 8, 1, "Opcion invalida                          ");
                wattroff(win, COLOR_PAIR(2));
                wgetch(win);
                werase(win);
                wrefresh(win);
            break;
    }
}
break;

            case '5':
                initscr();
                cbreak();
                echo();
                curs_set(0);
                keypad(stdscr, TRUE); //Habilitar teclas especiales como arriba o abajo
                win = newwin(10, 43, 0, 80); //Ventana de 30x10 en la posicion (0,0)
                box(win, 0, 0);
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, 1, 1, "Ingrese el nombre del archivo para       ");
                mvwprintw(win, 2, 1, "exportar los datos utilize la extencion  ");
                mvwprintw(win, 3, 1, ".csv:                                    ");

                mvwscanw(win, 3, 7, "%s", filename);
                wattroff(win, COLOR_PAIR(2));

                // Verificar que el nombre del archivo termine con ".csv"
                char *ext = strrchr(filename, '.');
                if (ext == NULL || strcmp(ext, ".csv") != 0) {
                wattron(win, COLOR_PAIR(2));
                    mvwprintw(win, 4, 1, "Error el archivo debe tener              ");
                    mvwprintw(win, 5, 1, "la extencion .csv                        ");
                wattroff(win, COLOR_PAIR(2));
                    wgetch(win);
                    werase(win);
                    wrefresh(win);
                break;
                }
                werase(win);
                wrefresh(win);
                 // Llamar a la nueva función de exportación
                export_data_csv(filename);
            break;

            case '6':
                pcap_close(dev);
                printf("Saliendo...\n");
                endwin();
                return 0;

            default:
                break;
        }
    }
}
