# Tabla de contenidos
1. [Criptografía](#Criptografía)
2. [Esteganografía](#Esteganografía)
3. [Forense](#Forense)
4. [Hacking Web](#Hacking-Web)
5. [OSINT](#OSINT)
6. [Exploiting (Pwning)](#Pwning)
7. [Reversing](#Reversing)
8. [Tráfico de Red](#Tráfico-de-Red)


# Criptografía

- [CyberChef](https://gchq.github.io/CyberChef/) - Potente herramienta en línea desarrollada por el GCHQ (Cuartel General de Comunicaciones del Reino Unido) que ofrece una amplia gama de capacidades de manipulación de datos para descifrar y codificar mensajes. Su interfaz intuitiva y fácil de usar permite a los usuarios explorar y aplicar una variedad de operaciones criptográficas y de codificación de manera rápida y eficiente. (página web).
- [Multisolver](https://geocaching.dennistreysa.de/multisolver/index.html) - Plataforma en línea que proporciona una variedad de herramientas para el cifrado, descifrado y análisis de mensajes y desafíos criptográficos. Esta plataforma está diseñada específicamente para resolver rompecabezas de geocaching y desafíos similares que requieren habilidades en criptografía y resolución de acertijos. (página web).
- [Hashcat](https://hashcat.net/hashcat/) - Herramienta de cracking de contraseñas que admite una amplia variedad de algoritmos de hash (herramienta de línea de comandos).
Ejemplo de uso: `hashcat -m 0 -a 0 hash.txt rockyou.txt` donde `hash.txt` es el archivo que contiene los hashes a crackear y `rockyou.txt` es el archivo que contiene la lista de contraseñas.
- [John the Ripper](https://www.openwall.com/john/) - Herramienta de cracking de contraseñas que admite varios tipos de cifrado y formatos de archivo (herramienta de línea de comandos). Ejemplo de uso: `john hash.txt` donde `hash.txt` es el archivo que contiene los hashes a crackear.

    - **WriteUps de ejemplo**:    
        - ![TheSenderConundrum](https://github.com/UchaCTF/WriteUps/tree/main/Forense/2023Vishwactf/TheSenderConundrum) (*Zip Cifrado*)
        
- [CryptoCorner](https://crypto.interactive-maths.com/) - Herramientas criptográficas y de codificación para ayudar a cifrar y descifrar datos. Algunas de las herramientas que ofrece son generadores de claves criptográficas, cifradores y descifradores de mensajes, y herramientas para el análisis de criptogramas. (página web)
- [AsecuritySite](https://asecuritysite.com/) - Sitio web que trata sobre seguridad de la información y criptografía. Contiene muchísima información y diferentes herramientas para el análisis y la protección de la información. (página web).
- [Boxentriq](https://www.boxentriq.com/) - Plataforma en línea que ofrece diversas herramientas y desafíos para el aprendizaje y la práctica de habilidades en áreas como la criptografía, la esteganografía y la resolución de acertijos. Entre sus herramientas se incluyen generadores de claves criptográficas, cifradores y descifradores de mensajes, y herramientas de análisis de criptogramas. (página web)
- [Dcode](https://www.dcode.fr/) -  plataforma en línea tipo cyberchef que proporciona una amplia variedad de herramientas criptográficas y de codificación para ayudar a cifrar y descifrar datos de forma segura. También ofrece herramientas para la resolución de acertijos y problemas matemáticos, así como para el análisis de criptogramas y códigos. Muy útil para [cifrados RSA](https://www.dcode.fr/rsa-cipher) (página web).

    - **WriteUps de ejemplo**:    
        - ![OverTheWire](https://github.com/albertominan/WriteUps/tree/main/Criptograf%C3%ADa/OverTheWire/Krypton) (*Análisis de frecuencia*)
        - ![Really-Small-Algorithm](https://github.com/UchaCTF/WriteUps/tree/main/Criptograf%C3%ADa/20230605-Hsctf/really-small-algorithm) (*Cifrado RSA*) 
      
      
# Esteganografía
- [Forensically](https://29a.ch/photo-forensics/#error-level-analysis) - Herramienta en línea para análisis forense de imágenes. Incluye funciones como análisis de nivel de error, detección de manipulación y más. (página web)
- [Stegonline](https://stegonline.georgeom.net/upload) - Plataforma en línea para la esteganografía, que permite ocultar y descubrir información en imágenes. Admite varios métodos de esteganografía. (página web)
- [Aperisolve](https://www.aperisolve.com/) - Aperi'Solve es una plataforma en línea que realiza análisis de capas en imágenes. La plataforma también utiliza zsteg, steghide, outguess, exiftool, binwalk, foremost y strings para un análisis más profundo de la esteganografía. Soporta los siguientes formatos de imagen: .png, .jpg, .gif, .bmp, .jpeg, .jfif, .jpe, .tiff... (página web)
- [Aspose Imaging](https://products.aspose.app/imaging/image-view) - Editor de imágenes en linea que permite múltiples acciones sobre imágenes: Conversión, Marca de agua, Búsqueda inversa de imágenes, Detección de objetos, Comprimir, Redimensionar, Recortar, Rotar e Invertir, Combinar, Enderezar, Eliminar fondo, Filtros, Divisor de Imágenes.(página web)
- [Steghide](http://steghide.sourceforge.net/) - Herramienta de esteganografía para ocultar datos en imágenes y archivos de audio (herramienta de línea de comandos).
Ejemplo de uso: `steghide extract -sf imagen.jpg` donde `imagen.jpg` es el archivo de imagen que contiene datos ocultos.
- [Exiftool](https://exiftool.org/) - Herramienta para leer y escribir metadatos en archivos de imagen, audio y video (herramienta de línea de comandos).
Ejemplo de uso: `exiftool archivo.jpg` donde `archivo.jpg` es el archivo de imagen del que deseas obtener información.

    - **WriteUps de ejemplo**:    
        - ![FindLocation](https://github.com/UchaCTF/WriteUps/tree/main/Esteganograf%C3%ADa/VU%20Cyberthon%202023)

- [Foremost](https://github.com/korczis/foremost) - Herramienta de recuperación de datos para extraer archivos de un sistema de archivos o una imagen de disco (herramienta de línea de comandos).
Ejemplo de uso: `foremost -t all -i imagen.dd` donde `imagen.dd` es la imagen de disco que deseas analizar.
- [Strings](https://linux.die.net/man/1/strings) - Utilidad de línea de comandos que puede buscar cadenas de texto en un archivo binario (herramienta de línea de comandos). Ejemplo de uso: `strings archivo.bin` donde `archivo.bin` es el archivo binario del que deseas extraer las cadenas de texto.
- [Audacity](https://www.audacityteam.org/) - Programa de edición y grabación de audio de código abierto y multiplataforma que permite modificar y analizar archivos de audio (aplicación de escritorio). 

    - **WriteUps de ejemplo**:    
        - ![CanYouSeeMe](https://github.com/UchaCTF/WriteUps/tree/main/Esteganograf%C3%ADa/2023Vishwactf/CanYouSeeMe) (*Análisis de espectro*)

- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Herramienta de análisis y extracción de firmware que permite identificar y extraer archivos y sistemas de archivos incrustados en imágenes de firmware (herramienta de línea de comandos). Ejemplo de uso: `binwalk -e firmware.bin` donde `firmware.bin` es el archivo de firmware que contiene archivos o sistemas de archivos incrustados.
- [EzGif](https://ezgif.com/split) - Herramienta en linea que permite extraer los farames de un Gif animado (paǵina web).

# Forense

#### Suites forenses

- [Autopsy](https://www.sleuthkit.org/autopsy/) - Herramienta de análisis forense que puede analizar imágenes de discos y sistemas de archivos (herramienta gráfica).

    - **WriteUps de ejemplo**:    
        - ![Forense en Windows](https://github.com/UchaCTF/WriteUps/tree/main/Forense/Windows/San%20Clemente%20CASO%20%232)

- [Bulk Extractor](https://github.com/simsong/bulk_extractor) - Herramienta de análisis forense digital que extrae automáticamente información como correos electrónicos, números de tarjeta de crédito y URLs de archivos, imágenes de disco y volcados de memoria (herramienta de línea de comandos). Ejemplo de uso: `bulk_extractor -o salida carpeta_imagen.dd` donde `salida` es la carpeta de destino para los resultados del análisis y `carpeta_imagen.dd` es la imagen de disco o archivo que se va a analizar.

- [OS Forensics](https://www.osforensics.com/) (versión de prueba limitada a 30 días)

- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-4-5) FTK Imager es una herramienta forense digital desarrollada por AccessData. Se utiliza comúnmente en el campo de la informática forense para adquirir y analizar datos de almacenamiento de medios digitales, como discos duros, dispositivos USB, tarjetas de memoria, entre otros.

- [SDL Redline](https://www.mandiant.com/resources/download/redline)

#### Análisis de memoria RAM

- [Volatility](https://www.volatilityfoundation.org/) - Herramienta de análisis de memoria para extraer información de la memoria volátil de un sistema (herramienta de línea de comandos).
Ejemplo de uso: `volatility -f memoria.mem imageinfo` donde `memoria.mem` es el archivo de imagen de memoria volátil que deseas analizar.

    - **WriteUps de ejemplo**:    
        - ![Forense en Windows](https://github.com/UchaCTF/WriteUps/tree/main/Forense/Windows/San%20Clemente%20CASO%20%232)

#### Montaje de imágenes

- [OSF Mount](https://www.osforensics.com/tools/mount-disk-images.html)

#### Editor hexadecimal de disco

- [Active disk Editor](https://www.disk-editor.org/)

#### Análisis de MFT

- [Mft2Csv_old](https://tzworks.net/prototype_page.php?proto_id=3)
- [Mft2Csv](https://github.com/jschicht/Mft2Csv/releases/tag/v2.0.0.49)

#### Análisis de LogFile y UsnJrnl

- [Log File Parser](https://github.com/jschicht/LogFileParser)
- [NTFS Log Tracker](https://github.com/jschicht/NTFS-Log-Tracker)

#### Análisis del registro de Windows

- [RegRipper](https://github.com/keydet89/RegRipper3.0)
- [Windows Registry Recover](https://www.nirsoft.net/utils/windows_registry_recovery.html)
- [Registry Explorer](https://ericzimmerman.github.io/#!index.md)
- [RECmd](https://ericzimmerman.github.io/#!index.md)
- [USBDeview](https://www.nirsoft.net/utils/usb_devices_view.html) (análisis de dispositivos USB)
- [USB Detective](https://www.13cubed.com/products) (análisis de dispositivos USB)

#### Análisis de los logs de windows (Event Log)

- [FullEventLogView](https://www.nirsoft.net/utils/full_event_log_view.html) de Nirsoft

#### Análisis de Prefetch y Superfetch

- [WindowsPrefetchView](https://www.nirsoft.net/utils/win_prefetch_view.html) de Nirsoft
- [CrowdResponse](https://www.crowdstrike.com/resources/community-tools/crowdresponse/)

#### Análisis del registro de actividad

- [Windows Timeline Parser](https://github.com/kacos2000/WindowsTimeline)
- [WxTCmd](https://github.com/EricZimmerman/WxTCmd)

#### Análisis de la papelera de reciclaje

- [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [RBCmd](https://github.com/kacos2000/RecycleBin)

#### Registros de seguimiento (Event Log Tracer, etl)

- [ETLParser](https://github.com/woanware/etlparser)

#### Navegadores Web

- [SQLite Studio](https://sqlitestudio.pl/)
- [IE HistoryView](https://www.nirsoft.net/utils/iehv.html) de Nirsoft
- [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) de Nirsoft
- [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) de Nirsoft
- [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) de Nirsoft
- [EdgeCookiesView](https://www.nirsoft.net/utils/edge_cookies_view.html) de Nirsoft
- [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) de Nirsoft
- [MZCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) de Nirsoft
- [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) de Nirsoft
- [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) de Nirsoft
- [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) de Nirsoft

#### Correo electrónico

- [PST Viewer](https://www.nucleustechnologies.com/pst-viewer.html)

# Hacking Web

- [Burp Suite](https://portswigger.net/burp) - Suite de herramientas de hacking web para probar y explotar vulnerabilidades en aplicaciones web (herramienta gráfica).
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - Herramienta de automatización de inyección SQL para probar vulnerabilidades en bases de datos (herramienta de línea de comandos).
Ejemplo de uso: `sqlmap -u "http://example.com/?id=1" --dbms=mysql --dump` donde `http://example.com/?id=1` es la URL de la aplicación web vulnerable, `--dbms=mysql` indica el tipo de base de datos y `--dump` indica que deseas descargar toda la información de la base de datos.
- [OWASP ZAP](https://www.zaproxy.org/) - Proxy de seguridad web de código abierto que se puede utilizar para encontrar y explotar vulnerabilidades (herramienta gráfica).
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Repositorio con una lista de payloads y bypasses útiles para Hacking Web (Repositorio Github y página Web).


# OSINT

- [The Harvester](https://github.com/laramies/theHarvester) - Herramienta de recopilación de información que puede buscar correos electrónicos, nombres de usuario, hostnames, etc. en fuentes públicas (herramienta de línea de comandos).
Ejemplo de uso: `theharvester -d example.com -l 500 -b google` donde `example.com` es el dominio que deseas analizar, `-l 500` indica que deseas limitar la salida a 500 resultados y `-b google` indica que deseas usar la búsqueda de Google.
- [Maltego](https://www.maltego.com/) - Herramienta de investigación y análisis de enlaces para recopilar información y relaciones en línea (herramienta gráfica).

# Pwning

- [GDB](https://www.gnu.org/software/gdb/) - Depurador de código abierto que puede ser útil para analizar y explotar vulnerabilidades en binarios ejecutables (herramienta de línea de comandos).
- [Pwndbg](https://github.com/pwndbg/pwndbg) - Una extensión de GDB diseñada para facilitar el debugging y la creación de exploits. Mejora la visualización de la información en GDB, haciendo más fácil entender lo que está ocurriendo y cómo se está modificando la memoria. Este depurador proporciona una serie de comandos y visualizaciones adicionales que simplifican y aceleran el proceso de explotación de binarios. Ideal para el análisis y la explotación de vulnerabilidades en binarios ejecutables (herramienta de línea de comandos).
- [Objdump](https://sourceware.org/binutils/docs/binutils/objdump.html) - Herramienta versátil de línea de comandos incluida en el conjunto de herramientas GNU Binutils. Objdump permite desensamblar secciones de código binario, mostrar el contenido de las secciones de datos, proporcionar información sobre las cabeceras del binario y mucho más. Es especialmente útil para la inspección rápida de binarios y para obtener una visión general de las secciones y rutinas de un ejecutable. Puede ser esencial al buscar vulnerabilidades en programas binarios o al intentar entender la estructura y el funcionamiento de estos (herramienta de línea de comandos).
- [Checksec](https://github.com/slimm609/checksec.sh) - Herramienta de comprobación de seguridad que muestra las diversas técnicas de mitigación que se han aplicado a un binario. Proporciona información sobre varias características de seguridad, como DEP (Data Execution Prevention), ASLR (Address Space Layout Randomization), canarios de stack, y RelRO (Relocation Read-Only). Esta herramienta es útil para entender qué medidas de protección están implementadas en un binario antes de intentar explotarlo, ayudando a planificar una estrategia de explotación adecuada (herramienta de línea de comandos).
- [Seccomp-tools](https://github.com/david942j/seccomp-tools) - Herramienta para trabajar con el sandboxing de seccomp (Secure Computing Mode). Seccomp es una característica del kernel de Linux que permite limitar las llamadas al sistema que un proceso puede realizar. Seccomp-tools permite a los usuarios volcar y desensamblar filtros de seccomp, así como trazar las llamadas al sistema bajo la política de seccomp. Es especialmente útil cuando se trata de analizar y explotar binarios que utilizan políticas de seccomp para limitar su comportamiento (herramienta de línea de comandos).
- [IDA Pro](https://www.hex-rays.com/products/ida/) - Desensamblador y depurador que puede ser útil para analizar binarios ejecutables y encontrar vulnerabilidades (herramienta gráfica).
- [Pwntools](https://github.com/Gallopsled/pwntools) - Marco de explotación para binarios ejecutables que puede ser útil para crear exploits (herramienta de línea de comandos).
Ejemplo de uso: `python -c "from pwn import *; print(hexdump(asm(shellcraft.sh())))"` para crear un exploit simple que ejecute una shell en el objetivo.

    - **WriteUps de ejemplo**:    
        - ![Leet1](https://github.com/UchaCTF/WriteUps/tree/main/Pwning/20230520-Cyberjousting/Leet1) (*Evaluación de expresión numérica - Python*)
        - ![Basic Pwn](https://github.com/UchaCTF/WriteUps/tree/main/Pwning/nusgreyhats%202023/bay%20pawn) (*Desbordamiento de enteros en C*)
        - ![Doubler](https://github.com/UchaCTF/WriteUps/blob/main/Pwning/20230605-Hsctf/doubler/Readme.md) (*Desbordamiento de enteros en C*)   
        - ![ed](https://github.com/UchaCTF/WriteUps/blob/main/Pwning/20230605-Hsctf/ed/Readme.md) (*Smashing the Stack*)
        - ![my first pwnie](https://github.com/UchaCTF/WriteUps/blob/main/Pwning/20230915-CSAW23/my_first_pwnie/Readme.md) (*Inyección de comandos*)
       
               

# Reversing

- [Ghidra](https://ghidra-sre.org/) - Marco de ingeniería inversa de código abierto que puede ser útil para analizar binarios ejecutables (herramienta gráfica).
- [Radare2](https://github.com/radareorg/radare2) - Marco de ingeniería inversa de código abierto que puede ser útil para analizar binarios ejecutables (herramienta de línea de comandos).
Ejemplo de uso: `r2 archivo` donde `archivo` es el archivo binario que deseas analizar.
- [IDA Pro](https://www.hex-rays.com/products/ida/) - Desensamblador y depurador que puede ser útil para analizar binarios ejecutables y encontrar vulnerabilidades (herramienta gráfica).
- [Cutter](https://cutter.re/) es una herramienta gráfica basada en radare2 que ofrece un entorno intuitivo y avanzado para el análisis y la ingeniería inversa de binarios. Con Cutter, puedes explorar la estructura del programa, realizar análisis estático, depurar en tiempo real, utilizar herramientas de ingeniería inversa y encontrar vulnerabilidades en binarios ejecutables de manera eficiente y efectiva.
- [virtual 6502 Disassembler](https://www.masswerk.at/6502/disassembler.html) - Herramienta en línea que permite desensamblar código para el procesador 6502. Puede ser útil para analizar programas escritos para este procesador y entender su funcionamiento interno. Esta herramienta te permite cargar tu código en formato hexadecimal y ver su representación desensamblada.

    - **WriteUps de ejemplo**:    
        - ![Pumpking](https://github.com/UchaCTF/WriteUps/tree/main/Reversing/20231111-CodeByGames-Cybercoliseum/ReverseEngineering/Pumpking) (*GHidra - Escritura en directorio /tmp*)

# Tráfico de Red

- [Tcpdump](https://www.tcpdump.org/) - Herramienta de línea de comandos para capturar y analizar el tráfico de red en tiempo real (herramienta de línea de comandos).
Ejemplo de uso: `tcpdump -i eth0 tcp port 80` donde `eth0` es la interfaz de red y `tcp port 80` indica que deseas capturar el tráfico TCP en el puerto 80.
- [Scapy](https://scapy.net/) - Herramienta de manipulación de paquetes de red que puede ser útil para crear y enviar paquetes personalizados (herramienta de línea de comandos).
Ejemplo de uso: `sudo scapy` para iniciar Scapy en modo interactivo y luego `send(IP(dst="www.google.com")/ICMP())` para enviar un paquete ICMP a la dirección IP de Google.
- [Wireshark](https://www.wireshark.org/) - Analizador de tráfico de red que puede ser útil para encontrar y analizar paquetes específicos (herramienta gráfica).

    - **WriteUps de ejemplo**:    
        - ![Inj3ct0r](https://github.com/UchaCTF/WriteUps/tree/main/Tr%C3%A1fico%20de%20Red/2023Vishwactf/inj3ct0r) (*Teclado USB*)
        - ![Lazy Admin](https://github.com/UchaCTF/WriteUps/tree/main/Tr%C3%A1fico%20de%20Red/0223Texsaw/Lazy%20Admin) (*URL Encoding*)
        - ![Security Flag](https://github.com/UchaCTF/WriteUps/tree/main/Tr%C3%A1fico%20de%20Red/2023LACTF-EBE) (*RFC 3514*)
        - ![Over The Wire I](https://github.com/UchaCTF/WriteUps/blob/main/Tr%C3%A1fico%20de%20Red/20231117-1337UP%20LIVE%20CTF-ctf.intigriti.io/Readme.md) (*Fichero ZIP cifrado*)
        - ![Over The Wire II](https://github.com/UchaCTF/WriteUps/blob/main/Tr%C3%A1fico%20de%20Red/20231117-1337UP%20LIVE%20CTF-ctf.intigriti.io-II/Readme.md) (*Esteganografía en SMTP*)


