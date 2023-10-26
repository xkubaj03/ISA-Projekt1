# ISA-Projekt1 (Netflow)
Netflow je software používaný na sběr informací o provozu v síti.
Program načítá (podle zadání TCP, UDP, ICMP) pakety, které zařazuje do flow a odesílá na 
kolektor. Zdroj je zadán přepínačem -f nebo defaultně STDIN.
Flow je jednoznačně rozlišitelná pomocí šestice zdrojová ip adresa, cílová ip adresa, zdrojový port, 
cílový port, ToS (type of service) a protokol (TCP, UDP a ICMP). Pakety jsou po jednom načítány a 
informace z nich jsou uládány do flows.
Pokud dojde k překročení intervalu active nebo inactive je danný flow odeslán na kolektor. 
Intervaly jsou určeny přepínači -a pro active a -i pro inactive . Pokud dojde k přeplnění cache je 
nejstarší flow odeslána. Maximální počet flows uchovávaných v cachi je určeno přepínačem -m.
Po zpracování všech paketů se odešle zbytek flows uložených cache a program se ukončí

## Použití
Program podporuje následující syntax pro spuštění:  
./flow [-f file] [-c netflow_collector[:port]] [-a active_timer] [-i inactive_timer] [-m 
count]

kde

- -f file jméno analyzovaného souboru nebo STDIN,
- -c neflow_collector:port IP adresa, nebo hostname NetFlow kolektoru. volitelně i UDP port 
(127.0.0.1:2055, pokud není specifikováno),
- -a active_timer interval v sekundách, po kterém se exportují aktivní záznamy na kolektor (60, 
pokud není specifikováno),
- -i seconds interval v sekundách, po jehož vypršení se exportují neaktivní záznamy na kolektor 
(10, pokud není specifikováno),
- -m count velikost flow-cache. Při dosažení max. velikosti dojde k exportu nejstaršího záznamu 
v cachi na kolektor (1024, pokud není specifikováno).
Všechny parametry jsou brány jako volitelné. Pokud některý z parametrů není uveden, použije se 
místo něj výchozí hodnota
