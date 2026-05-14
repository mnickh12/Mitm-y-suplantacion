#set page(paper: "a4", margin: 2.5cm)
#set text(font: "Times New Roman", size: 12pt)
#set par(justify: true, leading: 0.5em)
#set heading(numbering: "1.")

#align(center)[
  #text(size: 18pt, weight: "bold")[TÉCNICAS DE HACKING]

  #v(1cm)
  #text(size: 16pt)[Práctica 3: MitM y Suplantación]

  #v(1.5cm)
  #text(size: 12pt)[Autor: Alfredo Robledano Abasolo]
  #text(size: 12pt)[Fecha: 14 de mayo de 2026]
  #text(size: 12pt)[Asignatura: Técnicas de Hacking]
]

#pagebreak

#outline(title: "Índice", depth: 2)

#pagebreak

= Resumen

Este trabajo aborda la implementación de un sistema de monitorización basado en firmas para la detección de ataques de envenenamiento ARP (ARP Spoofing) en capa 2 y técnicas de reconocimiento mediante DNS, como el ataque de Kaminsky y el DNS Snooping.

Se han diseñado dos escenarios de red virtualizados mediante Docker Compose. El primero simula un ataque Man-In-The-Middle (MITM) mediante suplantación ARP, mientras que el segundo reproduce ráfagas de consultas DNS a subdominios inexistentes.

Para cada escenario se ha desarrollado un detector basado en Scapy que analiza el tráfico en tiempo real y emite alertas al identificar patrones maliciosos. Los resultados obtenidos demuestran la efectividad de las firmas implementadas para detectar ambos tipos de ataques en entornos controlados.

#pagebreak

= Introducción

== Contexto y motivación

En la actualidad, las redes locales siguen siendo vulnerables a ataques de capa 2 como el envenenamiento ARP, que permite a un atacante interceptar, modificar o bloquear el tráfico entre dos hosts legítimos. Este ataque constituye la base para escenarios de Man-In-The-Middle (MITM) y puede tener graves consecuencias en términos de confidencialidad e integridad de la información.

Por otro lado, el protocolo DNS es un vector de ataque frecuentemente explotado. El ataque de Kaminsky aprovecha debilidades en la resolución de consultas DNS para envenenar la caché de un servidor recursivo, mientras que el DNS Snooping permite a un atacante mapear la infraestructura interna de una organización mediante consultas masivas a subdominios inexistentes.

== Objetivos

Los objetivos de esta práctica son:

- Diseñar e implementar un sistema de detección de intrusiones (IDS) basado en firmas para ataques ARP Spoofing.
- Desarrollar un detector de ráfagas DNS sospechosas mediante umbrales de volumen.
- Validar ambos sistemas en entornos controlados con Docker.
- Comprender el impacto y la metodología de estos ataques en redes reales.

= Desarrollo

== Parte 1: Detección de envenenamiento ARP

=== Escenario de red

Se ha diseñado una topología de red virtual utilizando Docker Compose que incluye cuatro contenedores:

- *víctima*: nodo objetivo del ataque ARP Spoofing.
- *router*: nodo que simula la puerta de enlace de la red local.
- *servidor_web*: nodo en una red externa que representa un servicio legítimo.
- *atacante*: nodo desde el que se ejecuta el ataque de suplantación.

Todos los contenedores se despliegan sobre una red bridge de Docker que simula una red local Ethernet.

=== Firma de detección

La detección de ARP Spoofing se basa en la monitorización de respuestas ARP (opcode = 2). En condiciones normales, cada dirección IP está asociada a una única dirección MAC. Cuando un atacante realiza envenenamiento, envía respuestas ARP falsas haciendo que una misma IP aparezca con múltiples MACs.

La función `alert_arpspoof` implementada en Scapy mantiene una tabla hash que asocia cada IP con el conjunto de MACs observadas. Si una IP presenta más de una MAC, se emite una alerta inmediata.

=== Herramientas de ataque

Para ejecutar el ataque se ha utilizado `arpspoof`, parte de la suite `dsniff`, una herramienta clásica de envenenamiento ARP que envía paquetes ARP Reply falsos a la víctima, haciéndole creer que el atacante es el router de la red.

== Parte 2: Suplantación y anomalías DNS

=== Escenario de red

El segundo escenario consta de dos contenedores Docker:

- *dns_resolver*: nodo que actúa como resolver DNS y desde el que se monitoriza el tráfico.
- *dns_servidor*: nodo que actúa como servidor DNS autoritativo.

=== Firma de detección

El DNS Snooping y el ataque de Kaminsky comparten un patrón común: la generación de un volumen anormalmente alto de consultas DNS a subdominios inexistentes. La firma implementada en `alert_dnssnooping` utiliza un mecanismo de umbral con ventana temporal:

- *Umbral*: 10 consultas
- *Ventana*: 5 segundos

Si un mismo origen supera este umbral, se emite una alerta. Este enfoque permite distinguir entre tráfico legítimo esporádico y una ráfaga maliciosa.

=== Relación con el ataque de Kaminsky

El ataque de Kaminsky explota la predictibilidad de los IDs de transacción DNS y el comportamiento de los resolvers recursivos. Un atacante envía múltiples consultas por subdominios falsos mientras simultáneamente inunda al resolver con respuestas falsas, tratando de adivinar el ID de transacción correcto.

La ráfaga de subdominios aleatorios es una firma característica de este ataque, y su detección mediante umbrales de volumen constituye una contramedida eficaz.

= Resultados

== Prueba 1: ARP Spoofing

Al ejecutar `arpspoof` desde el contenedor atacante contra la víctima, el monitor captura respuestas ARP con la IP del router (172.18.0.5) provenientes de dos MACs distintas: la legítima del router y la del atacante. La alerta se dispara inmediatamente al detectarse la segunda MAC.

El ataque MITM se confirma al observar los mensajes ICMP Redirect en el ping desde la víctima hacia el router, indicando que el tráfico está siendo redirigido a través del atacante.

== Prueba 2: DNS Snooping

El generador de tráfico envía 15 consultas DNS a subdominios aleatorios en un intervalo de 3 segundos. Al superar el umbral de 10 consultas en la ventana de 5 segundos, el monitor emite la alerta correspondiente.

== Tabla resumen

#figure(
  caption: [Resumen de pruebas realizadas.],
  table(
    columns: 4,
    [*Ataque*], [*Herramienta*], [*Firma*], [*Efectividad*],
    [ARP Spoofing], [arpspoof], [Múltiples MACs por IP], [100%],
    [DNS Snooping], [Scapy], [Threshold de consultas], [100%],
  )
)

= Conclusiones

Esta práctica ha permitido implementar y validar dos sistemas de detección de intrusiones basados en firmas para ataques comunes en redes locales:

1. *ARP Spoofing*: La monitorización de anomalías en las tablas ARP resulta un método sencillo pero altamente eficaz para detectar ataques de envenenamiento. La firma basada en múltiples MACs por IP detecta el ataque de forma inmediata y sin falsos positivos en el entorno controlado.

2. *DNS Snooping*: La detección por umbral de volumen permite identificar ráfagas de consultas a subdominios inexistentes, patrón característico del ataque de Kaminsky y del reconocimiento DNS. La ventana temporal de 5 segundos y el umbral de 10 consultas ofrecen un equilibrio entre sensibilidad y resistencia a falsos positivos.

Como trabajo futuro, se plantea la implementación de mecanismos de respuesta automática, como el bloqueo dinámico del puerto del switch ante ARP Spoofing, o la inclusión de listas blancas de subdominios legítimos en el detector DNS.
