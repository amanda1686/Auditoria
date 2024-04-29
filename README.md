# Auditoría Abooks

![image](https://github.com/amanda1686/Auditoria/assets/80174591/d16c7faf-8254-45c8-a338-c7a05ca0243b)


**Auditoría y ciberseguridad en la web** 

La auditoría y ciberseguridad en la web es un área de creciente importancia. Con el aumento de las amenazas cibernéticas, es crucial que las empresas adopten medidas de seguridad robustas para proteger su información y sistemas.

Linux, un sistema operativo de código abierto, ofrece una variedad de herramientas y características que pueden ayudar a fortalecer la ciberseguridad. A través de su naturaleza de código abierto, Linux permite a los usuarios modificar y mejorar sus sistemas de seguridad para adaptarse a sus necesidades específicas.

La auditoría en Linux puede ayudar a las empresas a identificar y gestionar posibles vulnerabilidades. Existen varias herramientas de auditoría disponibles para Linux, como Lynis y Tiger, que pueden realizar una serie de pruebas de seguridad para identificar posibles problemas.

En conclusión, la combinación de auditoría y ciberseguridad en la web con Linux puede proporcionar un enfoque robusto y personalizable para proteger los sistemas y datos de las amenazas cibernéticas.

# Índice

1. Análisis de la web a través de terminal
2. Owasp Zap vulnerabilidades
3. Owasp Zap informe
4. Burpsuite
5. Medidas de seguridad en el código

**nslookup** [https://abooks.onrender.com/](https://abooks.onrender.com/). Conocer la IP y dominio 

![image](https://github.com/amanda1686/Auditoria/assets/80174591/c7469cf3-a60a-40da-ac96-4216d38749a9)


## **nikto**

![image](https://github.com/amanda1686/Auditoria/assets/80174591/587cc382-c8bb-4b03-9f3e-ffd307be2029)


1. **Fecha y hora de inicio del escaneo**: El escaneo comenzó el **domingo 28 de abril de 2024 a las 07:33:14 (GMT+4)**.
2. **IPs asociadas al objetivo**:
    - 216.24.57.4
    - 216.24.57.252
3. **Información SSL**:
    - Sujeto: **/C=US/ST=California/L=San Francisco/O=Cloudflare, Inc./CN=onrender.com**
    - Cifras: **TLS_AES_256_GCM_SHA384**
    - Emisor: **/C=US/O=Cloudflare, Inc./CN=Cloudflare Inc ECC CA-3**
4. **Servidor**:
    - Alojado en **Cloudflare**.
    - Encabezado **x-powered-by**: Express.
    - El encabezado **X Frame Options** (anti-clickjacking) no está presente.
    - Encabezado no común **rnd-id**: 95c3888e–16b0–47f4.
    - Encabezado no común **x-render-origin-server**: Render.
    - El sitio utiliza TLS, pero el encabezado **Strict Transport Security** no está definido.
    - [Se encontró un encabezado **alt-svc** que anuncia HTTP/3, pero Nikto no puede probar HTTP/3](https://blog.csdn.net/leiwuhen92/article/details/128394254)

**curl -I** [https://abooks.onrender.com/](https://abooks.onrender.com/).El argumento **`-I`** (o **`--head`**) le indica a **`curl`** que solicite solo las cabeceras HTTP

![image](https://github.com/amanda1686/Auditoria/assets/80174591/cad447fb-8e41-42e3-a461-815fb81a69fb)

1. **Fecha y hora de la respuesta**: El servidor respondió a la solicitud el **domingo 28 de abril de 2024 a las 11:35:25 GMT**.
2. **Tipo de contenido**: El contenido devuelto es de tipo **“text/html”** con codificación **UTF-8**.
3. **Estado de caché**: El estado de caché se establece como **“DYNAMIC”**.
4. **ETag**: El valor del ETag es **"W/“188-18dcb83bd28"”**.
5. **Última modificación**: La última modificación del recurso fue el **miércoles 21 de febrero de 2024 a las 11:53:45 GMT**.
6. **Variaciones**: El servidor puede variar la respuesta según la codificación de aceptación.
7. **Servidor**: El servidor está alimentado por **Express** y protegido por **Cloudflare**.

## **whatweb IP address**
![image](https://github.com/amanda1686/Auditoria/assets/80174591/f8f52a9d-49bd-4bc6-b11c-1cac5d7f9f07)
- **URL:** [https://abooks.onrender.com/](https://abooks.onrender.com/)
- **Estado de Respuesta:** 200 OK
- **País:** Estados Unidos (UNITED STATES)
- **Tecnologías Detectadas:**
    - HTML5
    - HTTPServer: Cloudflare
    - Script: Módulo
    - X-Powered-By: Express
- **Dirección IP:** 216.24.57.252
- **Títutlo de la Página:** A-Books
- **Encabezados No Comunes:**
    - cf-ray
    - cf-cache-status
    - rndr-id
    - x-render-origin-server
    - alt-svc

## **Wappalyzer**

![image](https://github.com/amanda1686/Auditoria/assets/80174591/36e03482-84f7-4f41-89de-fa2e9a243cea)


Mediante esta herramienta podemos ver las tecnologías utilizadas.

## **Shodan**

![image](https://github.com/amanda1686/Auditoria/assets/80174591/1e37919f-9ce0-4e5a-aef1-a3edaf44c805)
![image](https://github.com/amanda1686/Auditoria/assets/80174591/ef832045-8c1b-49a5-a44c-6489fd984428)

### Informe de la Dirección IP: 216.24.57.4

### Información General

- **Hostname**: summit.credo.ai
- **Dominios**: CREDO.AI
- **País**: Estados Unidos
- **Ciudad**: San Francisco
- **Organización**: Render

### Puertos Abiertos

Los siguientes puertos están abiertos en la dirección IP:

- 80
- 443
- 2082
- 2083
- 2086
- 2087
- 8443
- 8880

### Información Adicional

- La dirección IP parece estar asociada con CloudFlare.
- Se ha detectado un error HTTP/1.1 403 Forbidden.

### Ubicación Geográfica

La ubicación geográfica asociada a la dirección IP parece estar en las áreas de Alameda y San Leandro, según el mapa satelital mostrado en la imagen.

## **nmap**

![image](https://github.com/amanda1686/Auditoria/assets/80174591/4997b5bf-b827-4ed2-89a6-e293d330190e)


- **Dirección IP escaneada**: 216.24.57.4
    
    **Detalles del Escaneo**
    
- **Versión de Nmap**: El escaneo se realizó utilizando Nmap versión 7.94SVN.
- **Fecha y Hora del Escaneo**: El escaneo se realizó el 28 de abril de 2024 a las 14:24 EDT.
- **Latencia**: La latencia de la dirección IP es de 0.016s, lo que indica una respuesta rápida.
    
    **Puertos Abiertos**
    
    Los siguientes puertos TCP están abiertos en la dirección IP:
    
- **Puerto 80**: Este puerto, que está asociado con el protocolo HTTP, está abierto.
- **Puerto 443**: Este puerto, que está asociado con el protocolo HTTPS, está abierto.
- **Puerto 8080**: Este puerto, que a menudo se utiliza para proxies HTTP, está abierto.
- **Puerto 8443**: Este puerto, que a menudo se utiliza como alternativa al puerto 443 para tráfico HTTPS, está abierto.
    
    **Puertos Filtrados**
    
    Además, se menciona que hay “996 puertos TCP filtrados (sin respuesta)”. Esto podría indicar que estos puertos están siendo bloqueados por un firewall u otra medida de seguridad.
    
- **Latencia del host**: 0.0016 segundos (0.0016s latency)
- **Tiempo de escaneo**: El escaneo se completó en 4.79 segundos.

**TheHarvester**
Se utilizó TheHarvester para recolectar información centrada en subdominios, direcciones de correo electrónico y otros datos en línea.

Se realizaron búsquedas en varios motores de búsqueda y fuentes de información, pero no se encontraron subdominios, direcciones de correo electrónico o hosts haciendo uso de esta herramienta.

![image](https://github.com/amanda1686/Auditoria/assets/80174591/15f5cf39-74d1-47f5-b65e-1f7c13b041ab)

### **OWASP amass**

![image](https://github.com/amanda1686/Auditoria/assets/80174591/809abaea-4614-4315-bd06-b85bd9ec07f4)

![image](https://github.com/amanda1686/Auditoria/assets/80174591/58492423-3a6b-45ad-870d-f4621f1ae4e5)

**subbrute.py.** Para obtener los subdominios

![image](https://github.com/amanda1686/Auditoria/assets/80174591/9f332900-06ff-471a-9cca-c7c94a68d870)

# Owasp Zap

OWASP (Open Web Application Security Project) es una comunidad global que se centra en mejorar la seguridad del software. Ofrece recursos, herramientas y conocimientos para desarrollar, adquirir y mantener aplicaciones web y APIs seguras. Sus objetivos incluyen educar sobre seguridad del software, desarrollar herramientas de código abierto, proporcionar documentación y fomentar la colaboración en la comunidad de seguridad. OWASP ZAP (Zed Attack Proxy) es una de sus herramientas más destacadas, diseñada para encontrar vulnerabilidades en aplicaciones web y APIs. Ofrece funciones como escaneo automático, pruebas de penetración manual e interceptación de solicitudes. OWASP desempeña un papel crucial al promover la conciencia sobre la seguridad del software y al proporcionar recursos para ayudar a construir aplicaciones web más seguras.

- **Ajax Spider**

![image](https://github.com/amanda1686/Auditoria/assets/80174591/3e09bc0d-e93d-41f7-acfc-2fbf5ca33eeb)

Informe de Análisis de Escaneo:

Fecha del Escaneo: 29 de abril de 2024

Herramienta Utilizada: OWASP ZAP (Zed Attack Proxy)

El escaneo realizado con OWASP ZAP se centró en la identificación de posibles vulnerabilidades en una serie de URL específicas. Se utilizaron diversas técnicas, incluyendo el escaneo AJAX Spider, para evaluar la seguridad de las aplicaciones web.

Detalles del Escaneo:

- Páginas Analizadas: Se procesaron un total de 9574 páginas únicas durante el escaneo.
- Solicitudes Procesadas: La tabla de solicitudes procesadas muestra múltiples solicitudes realizadas a diversas URL, incluyendo solicitudes GET y POST. Se observaron varios códigos de respuesta HTTP, como 403 (Prohibido) y 304 (No modificado), lo que sugiere posibles problemas de acceso y modificaciones no autorizadas.
- AJAX Spider: Se utilizó la función AJAX Spider para manejar aplicaciones web que hacen uso intensivo de tecnologías AJAX. Esto permitió un análisis más exhaustivo de las aplicaciones web, especialmente aquellas que actualizan dinámicamente partes de la página sin recargarla por completo.
- Alertas: Se generaron varias alertas durante el escaneo, indicando posibles vulnerabilidades o irregularidades en las aplicaciones web escaneadas. Se deben investigar y abordar estas alertas para mejorar la seguridad de las aplicaciones.

Conclusiones:

El escaneo realizado con OWASP ZAP proporcionó información valiosa sobre posibles vulnerabilidades y áreas de mejora en las aplicaciones web analizadas. Se recomienda realizar acciones correctivas para abordar las alertas generadas y fortalecer la seguridad de las aplicaciones.

- **Spider de OWASP ZAP**
    
    ![image](https://github.com/amanda1686/Auditoria/assets/80174591/362c7112-1cd5-41f6-bb26-b92aa9d1098f)

  
El Spider de OWASP ZAP es una herramienta de escaneo estático que explorar páginas web de forma exhaustiva, identificando recursos y posibles vulnerabilidades. Se enfoca en seguir enlaces estáticos dentro del código HTML para mapear la estructura de la aplicación. Es eficaz para identificar recursos estáticos y páginas accesibles a través de enlaces convencionales. Sin embargo, no es tan efectivo para aplicaciones web que utilizan tecnologías AJAX u otras técnicas de actualización dinámica de contenido. A diferencia del AJAX Spider, no puede manejar correctamente las interacciones dinámicas entre el cliente y el servidor. Es una herramienta útil para el análisis de aplicaciones web estáticas y puede integrarse con otras funciones de OWASP ZAP para proporcionar un análisis completo de la seguridad.

Informe de Escaneo de OWASP ZAP:

Fecha del Escaneo: 29/04/2024

Herramienta Utilizada: OWASP ZAP (Zed Attack Proxy)

Resumen:

El escaneo realizado con OWASP ZAP se centró en el análisis de la aplicación web alojada en "https://albooks.onrender.com/". Se utilizó tanto el Spider tradicional como el AJAX Spider para explorar las páginas y recursos disponibles. Se identificaron diversas URLs, incluyendo archivos de sitemap y robots.txt, así como recursos estáticos como archivos CSS y JavaScript. Se detectaron algunos nodos inaccesibles o fuera de alcance durante el escaneo.

Detalles del Escaneo:

- Páginas Analizadas: Se completó el escaneo del 100% de las URLs encontradas (30 URLs en total), con 4 nodos ingresados durante el proceso.
- Métodos Utilizados: Se utilizaron principalmente solicitudes GET para acceder a las distintas URLs y recursos de la aplicación.
- Vulnerabilidades Detectadas: No se reportaron alertas de vulnerabilidades durante el escaneo, aunque se identificaron algunos nodos inaccesibles o fuera del ámbito deseado.

Conclusiones:

El escaneo realizado proporcionó una visión general de la estructura y los recursos disponibles en la aplicación web analizada. Se recomienda revisar los nodos inaccesibles y fuera del ámbito para garantizar una cobertura completa del escaneo. Es importante realizar un seguimiento continuo de la seguridad de la aplicación y abordar cualquier posible vulnerabilidad detectada.

- **Alertas**

![image](https://github.com/amanda1686/Auditoria/assets/80174591/d8a420c5-ec0c-477a-bc3b-d5a4db561138)

El informe del escaneo realizado con OWASP ZAP muestra análisis detallados de dos sitios: "[https://apis.google.com](https://apis.google.com/)" y "[https://abooks.onrender.com](https://abooks.onrender.com/)". Se encontraron un total de 10 alertas, distribuidas en distintos niveles de riesgo y confianza.

Para el sitio "[https://apis.google.com](https://apis.google.com/)", se detectó una configuración incorrecta de Cross-Domain, una falta de cabecera Anti-Clickjacking y un archivo oculto encontrado. Estas alertas tienen un nivel de riesgo medio.

En cuanto al sitio "[https://abooks.onrender.com](https://abooks.onrender.com/)", se identificaron múltiples problemas, incluyendo divulgación de información a través del encabezado HTTP "X-Powered-By", la falta de la cabecera Strict-Transport-Security, y la ausencia de la cabecera X-Content-Type-Options. Estas alertas se clasificaron como de bajo riesgo.

Además, se reportaron alertas informativas sobre una posible aplicación web moderna y la necesidad de reexaminar las directivas de Cache-control.

En resumen, el informe destaca varias áreas de preocupación en la seguridad de los sitios analizados, proporcionando información valiosa para mejorar su robustez y mitigar posibles vulnerabilidades.

Para ampliar información sobre el informe realizado por OwasZap en el siguiente enlace.

**[ZAP Informes de Escaneo](https://drive.google.com/file/d/1vKBOYxBlYM2m4__zZq-BcpuIjndDwXeE/view?usp=sharing)**

# Burp Suite

Burp Suite es una suite de herramientas de prueba de penetración utilizada principalmente para evaluar la seguridad de aplicaciones web. Ofrece funcionalidades como el proxy HTTP/S, el escaneo de vulnerabilidades, la intrusión de datos, y más. Permite interceptar y modificar el tráfico entre el navegador y el servidor para analizar las solicitudes y respuestas HTTP. Su función de Spider explora automáticamente la aplicación web para mapear su estructura y encontrar posibles puntos de entrada. La herramienta de escaneo identifica vulnerabilidades como inyecciones SQL, XSS y CSRF, proporcionando informes detallados. Burp Suite también incluye extensiones personalizables que permiten ampliar su funcionalidad según las necesidades del usuario. Es ampliamente utilizada por profesionales de seguridad informática y probadores de penetración para evaluar la seguridad de aplicaciones web.

![image](https://github.com/amanda1686/Auditoria/assets/80174591/018da4ad-ca55-4935-a477-6af261290333)

### Informe de Burp Suite

**Resumen General:** La captura de pantalla muestra la interfaz de usuario de Burp Suite, una herramienta avanzada para pruebas de seguridad en aplicaciones web. Se observan varias pestañas que indican las diferentes funcionalidades del programa, como “Dashboard”, “Target”, “Proxy”, entre otras.

**Historial HTTP:** En la parte superior, hay una tabla con el historial de solicitudes HTTP, mostrando detalles como el método, la URL, el código de estado y la longitud de la respuesta.

**Solicitud y Respuesta HTTP:**

- **Solicitud (Request):** Se muestra una solicitud HTTP detallada con encabezados y parámetros. La solicitud parece ser un método GET a un endpoint específico, con varios encabezados que incluyen el tipo de contenido y la longitud del contenido.
- **Respuesta (Response):** A la derecha de la solicitud, se muestra una respuesta HTTP. Los encabezados y el cuerpo de la respuesta están presentes, con partes del cuerpo resaltadas en rojo, lo que podría indicar información sensible o puntos de interés para las pruebas de seguridad.

**Detalles Técnicos:**

- La solicitud HTTP incluye encabezados como **`User-Agent`**, **`Accept-Language`**, **`Content-Type`**, entre otros.
- La respuesta HTTP tiene un código de estado 200 OK, lo que generalmente indica que la solicitud fue exitosa.

**Análisis de Seguridad:** La imagen sugiere que se está realizando un análisis de seguridad, posiblemente revisando las solicitudes y respuestas para identificar vulnerabilidades o problemas de seguridad en la aplicación web objetivo.

![image](https://github.com/amanda1686/Auditoria/assets/80174591/cc34f48c-5ea7-4ee8-980a-238815b6928b)


### Análisis de Solicitud y Respuesta API

**Solicitud (Request):**

- **Tipo de Solicitud:** POST /api/auth/signin HTTP/2
- **Host:** abooks.onrender.com
- **User-Agent:** Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/115.0
- **Accept:** */*
- **Accept-Language:** en-US,en;q=0.5
- **Accept-Encoding:** gzip, deflate,
- **Referer:** [Página de inicio de sesión](https://abooks.onrender.com/signin)
- **Content-Type:** application/json
- **Content-Length:** 51
- **Origin:** [Página principal](https://abooks.onrender.com/)
- **Cuerpo de la Solicitud:** Contiene datos JSON con una dirección de correo electrónico y una contraseña (oculta por asteriscos).

**Respuesta (Response):**

- **Estado:** HTTP/2 200 OK
- **Fecha:** Mon, 29 Apr 2024 20:21:10 GMT
- **Content-Type:** application/json; charset=utf-8
- **CF-Ray:** 87c1ffddbaeal-MAD
- **Etag:** "W/“ce-lz3sT6gGkFKTt7NaxlLUBZM…”
- **Set-Cookie:** access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…
- **Cuerpo de la Respuesta:** Contiene datos JSON con información del usuario como ID, nombre de usuario, dirección de correo electrónico y una URL a una imagen de perfil.

**Observaciones de Seguridad:**

- La solicitud POST indica un proceso de autenticación de usuario.
- La respuesta exitosa sugiere que las credenciales proporcionadas son válidas.
- Es importante asegurarse de que la contraseña esté adecuadamente protegida y no se exponga en logs o capturas de pantalla.
- La presencia del token de acceso en la respuesta requiere un manejo seguro para prevenir riesgos de seguridad como el robo de sesión.

![Untitled](Auditori%CC%81a%20Abooks%20e213ff7d251e40688420c8c33f30d2e2/Untitled%2019.png)

### Informe de Análisis de Burp Suite

**Resumen General:** La captura de pantalla muestra la interfaz de usuario de Burp Suite, una herramienta de pruebas de seguridad web. Se destacan varias pestañas que representan las funcionalidades del programa, como “Dashboard”, “Target”, “Proxy”, “Intruder”, entre otras.

**Historial HTTP:** Se observa una sección titulada “HTTP history” que lista un historial de solicitudes HTTP, con detalles como el método (GET/POST), URL, parámetros, estado del código HTTP y longitud del mensaje.

**Detalles de la Solicitud HTTP:**

- **Filtro:** Se aplicó un filtro para ocultar contenido CSS, imágenes y contenido binario general.
- **Solicitud Seleccionada:** En la parte inferior, se muestra una solicitud HTTP específica con detalles en formatos como “Raw”, “Headers”, “Hex”, etc.
- **Inspector:** A la derecha, hay un panel titulado “Inspector” que muestra atributos detallados relacionados con las cookies y encabezados de las solicitudes HTTP.

**Análisis Técnico:**

- **Método:** POST
- **Tipo de Contenido:** application/x-www-form-urlencoded
- **Estado del Código:** 200 OK
- **Tipo MIME:** JSON
- **Cookies:** Se identifica un token de acceso JWT en las cookies.

![Untitled](Auditori%CC%81a%20Abooks%20e213ff7d251e40688420c8c33f30d2e2/Untitled%2020.png)

### Análisis de Herramienta JWT

**Resumen General:** La captura de pantalla muestra la interfaz de una herramienta de software utilizada para probar o depurar JSON Web Tokens (JWTs). Esta herramienta es útil para desarrolladores que trabajan con autenticación y autorización en aplicaciones web.

**Interfaz de Usuario:**

- **Sección de Solicitud (Request):** En el lado izquierdo, hay campos para ingresar datos y botones como “Enviar” y “Cancelar”, lo que sugiere que se pueden enviar JWTs para su prueba o validación.
- **Visualización de JWT:** En el centro, se muestra un JWT en diferentes formatos, incluyendo “JSON Web Tokens”, “JSON Web Token” y cadenas codificadas.
- **Opciones de Modificación:** Hay opciones para modificar automáticamente la firma, reemplazar la firma original, mantener la firma original, firmar con un par de claves aleatorio o cargar un secreto/clave desde un archivo.
- **Cadena JWT Codificada:** Se muestra una cadena JWT codificada en la sección inferior.

**Panel Inspector:**

- **Objetivo:** El panel “Inspector” apunta a “[books.oneword.com](https://books.oneword.com/)”.
- **Pestañas Vacías:** Las pestañas para atributos de solicitud, parámetros de consulta, parámetros del cuerpo, cookies y encabezados están vacías, lo que indica que no se ha realizado ninguna solicitud o que los detalles no se han capturado.

**Registro de Eventos:**

- **Pestaña ‘Event log’:** Muestra que está listo, lo que podría indicar que la herramienta está preparada para recibir y procesar JWTs.
- **Pestaña ‘All issues’:** Junto a ella, sugiere que la herramienta puede identificar y listar problemas relacionados con los JWTs procesados.

**Observaciones de Seguridad:**

- La herramienta parece ser capaz de manejar JWTs, lo que es esencial para la seguridad en aplicaciones que utilizan este tipo de tokens para la autenticación y autorización.
- Es importante que cualquier JWT manejado por esta herramienta se trate con cuidado para evitar la exposición de información sensible.

# Medidas de seguridad en el código

1. Validación de entrada: Verificar y sanitizar los datos recibidos para prevenir inyecciones de código malicioso como SQL o XSS.
2. Escapado de salida: Codificar datos antes de enviarlos al navegador para evitar ataques de XSS.
3. Uso de parámetros preparados en consultas SQL para evitar inyecciones de SQL.
4. Implementación de control de acceso y autenticación adecuados para proteger recursos sensibles.
5. Habilitar encabezados de seguridad HTTP como Content Security Policy (CSP) y HTTP Strict Transport Security (HSTS).
6. Actualización regular de dependencias y bibliotecas para parchear vulnerabilidades conocidas.
7. Uso de cifrado adecuado para proteger datos sensibles en tránsito y en reposo.
8. Validación de token CSRF para prevenir ataques de falsificación de solicitudes entre sitios.
9. Limitar los privilegios de acceso a recursos y funciones según el principio de menor privilegio.
10. Realización de pruebas de seguridad regulares, como pruebas de penetración y análisis estático de código, para identificar y abordar posibles vulnerabilidades.

![Untitled](Auditori%CC%81a%20Abooks%20e213ff7d251e40688420c8c33f30d2e2/Untitled%2021.png)

**Resumen General:** El código pertenece a un archivo de rutas llamado “auth.Routes.js” para un servidor web creado con Express.js. Este archivo se encarga de definir las rutas de autenticación para la aplicación.

**Detalles del Código:**

**JavaScript**

`import express from 'express';
import { google, login, register } from '../controllers/auth.Controller.js';
import { limitLogin } from '../middlewares/timeout.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', limitLogin, login);
router.post('/google', google);

export default router;`

Código generado por IA. Revisar y usar cuidadosamente. [Más información sobre preguntas frecuentes](https://www.bing.com/new#faq).

**Análisis Técnico:**

- **Importaciones:** El archivo importa el módulo **`express`** y varias funciones de controladores y middlewares.
- **Router:** Se crea una instancia del router de Express para manejar las rutas HTTP POST.
- **Rutas Definidas:**
    - **/register:** Ruta para el registro de usuarios, utiliza la función **`register`**.
    - **/login:** Ruta para el inicio de sesión, utiliza un middleware **`limitLogin`** para limitar intentos de acceso y la función **`login`**.
    - **/google:** Ruta para la autenticación con Google, utiliza la función **`google`**.
- **Exportación:** El router se exporta como el export por defecto del módulo, lo que permite su uso en otras partes de la aplicación.

**Observaciones de Seguridad:**

- **Middleware de Límite de Inicio de Sesión:** El uso de **`limitLogin`** sugiere una preocupación por la seguridad, posiblemente para prevenir ataques de fuerza bruta.
- **Autenticación con Google:** La ruta ‘/google’ indica que la aplicación soporta inicio de sesión con cuentas de Google, lo cual es una práctica común para simplificar el proceso de autenticación.

![Untitled](Auditori%CC%81a%20Abooks%20e213ff7d251e40688420c8c33f30d2e2/Untitled%2022.png)

El "**npm rate limi**t" es una medida implementada por npm (Node Package Manager) para evitar un uso excesivo de los recursos del servicio. Cuando se alcanza el límite de tasa, npm restringe temporalmente ciertas acciones, como la instalación o la publicación de paquetes. Esto se hace para proteger la infraestructura de npm y garantizar un servicio equitativo para todos los usuarios. Los límites de tasa varían según el tipo de cuenta de npm y pueden cambiar con el tiempo. Los usuarios pueden ver sus límites de tasa actuales utilizando el comando "npm limits" en la línea de comandos. Si se alcanza el límite de tasa, los usuarios pueden esperar unos minutos o pueden considerar actualizar a una cuenta de pago para obtener límites de tasa más altos. En resumen, el npm rate limit es una medida para evitar un uso excesivo de los recursos y garantizar un servicio estable para todos los usuarios de npm.

### Análisis de Código: timeout.js

**Resumen General:** El código pertenece a un archivo llamado “timeout.js”, que parece ser parte de la carpeta “middlewares” en un servidor Express.js. Este archivo se utiliza para definir limitaciones en las solicitudes de inicio de sesión para mejorar la seguridad.

**Detalles del Código:**

**JavaScript**

`import { rateLimit } from 'express-rate-limit';

// Declaro una variable para usar luego en mi controlador de auth, y definir el tiempo de expiración de un token
export const tokenExpirationTime = 3 * 60 * 60 * 1000; // 3 horas

// Uso la librería ratelimit para definir la cantidad de intentos que se pueden hacer en el login
export const limitLogin = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 3, // Máximo número de intentos de inicio de sesión
    message: 'Too many fail requests, try in again in 15 minutes',
});`

Código generado por IA. Revisar y usar cuidadosamente. [Más información sobre preguntas frecuentes](https://www.bing.com/new#faq).

**Análisis Técnico:**

- **Importación:** El archivo importa la función **`rateLimit`** de la librería ‘express-rate-limit’.
- **tokenExpirationTime:** Se declara una constante para definir el tiempo de expiración de un token, establecido en 3 horas.
- **limitLogin:** Se declara otra constante que utiliza **`rateLimit`** para limitar los intentos de inicio de sesión a un máximo de 3 cada 15 minutos.

**Observaciones de Seguridad:**

- **Limitación de Intentos:** La limitación de intentos de inicio de sesión es una medida de seguridad importante para prevenir ataques de fuerza bruta.
- **Mensaje de Error:** El mensaje proporcionado informa al usuario que ha excedido el número de intentos permitidos y debe esperar 15 minutos antes de intentar nuevamente.

![Untitled](Auditori%CC%81a%20Abooks%20e213ff7d251e40688420c8c33f30d2e2/Untitled%2023.png)

### Análisis de Código: Función de Inicio de Sesión

**Resumen General:** El código muestra una función asincrónica llamada **`login`** que maneja el proceso de inicio de sesión de un usuario en una aplicación web.

**Detalles del Código:**

**JavaScript**

`export const login = async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password || email === '' || password === '') {
        next(errorHandler(400, 'All fields are required'));
    }
    try {
        const validUser = await User.findOne({ email });
        if (!validUser) {
            return next(errorHandler(404, 'User not found'));
        }
        const validPassword = bcryptjs.compareSync(password, validUser.password);
        if (!validPassword) {
            return next(errorHandler(404, 'Invalid password'));
        }
        const token = jwt.sign(
            { id: validUser._id, isAdmin: validUser.isAdmin },
            process.env.JWT_SECRET,
            { algorithm: 'RS256' },
            { expiresIn: tokenExpirationTime },
        );
        const { password: pass, ...rest } = validUser._doc;
        res.status(200).cookie('access_token', token, { httpOnly: true }).json(rest);
    } catch (error) {
        next(error);
    }
};`

Código generado por IA. Revisar y usar cuidadosamente. [Más información sobre preguntas frecuentes](https://www.bing.com/new#faq).

**Análisis Técnico:**

- **Validaciones:** Se realizan comprobaciones para asegurar que se proporcionen el correo electrónico y la contraseña.
- **Búsqueda de Usuario:** Se utiliza **`User.findOne`** para buscar al usuario en la base de datos por su correo electrónico.
- **Verificación de Contraseña:** Se compara la contraseña proporcionada con la almacenada en la base de datos usando **`bcryptjs`**.
- **Generación de JWT:** Si las credenciales son válidas, se genera un JWT para gestionar la sesión del usuario.
- **Respuesta:** Se envía una respuesta con el estado HTTP 200 y se incluye el token en una cookie HTTP-only para mejorar la seguridad.

**Observaciones de Seguridad:**

- **Manejo de Contraseñas:** El uso de **`bcryptjs`** para comparar contraseñas es una práctica segura para proteger las credenciales de los usuarios.
- **Cookies HTTP-only:** El token se envía en una cookie HTTP-only, lo que ayuda a proteger contra ataques de tipo XSS.

![Untitled](Auditori%CC%81a%20Abooks%20e213ff7d251e40688420c8c33f30d2e2/Untitled%2024.png)

### Análisis de Código: Función de Registro

**Resumen General:** El código muestra una función asincrónica llamada **`register`** que maneja el registro de nuevos usuarios en una aplicación web.

**Detalles del Código:**

**JavaScript**

`export const register = async (req, res, next) => {
    // Ejecuta las validaciones definidas en las rutas
    const errors = validationResult(req);
    // Verifica si hay errores y retorna una respuesta en código 422 y los errores
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }
    // Si no hay errores de validación, procede con el registro del usuario
    const { username, lastname, email, password } = req.body;
    // Validaciones adicionales (por ejemplo, comprobación de campos vacíos)
    if (!username || !lastname || !email || !password || username === '' || lastname === '' || email === '' || password === '') {
        return next(errorHandler(400, 'All fields are required'));
    }
    // Hash de la contraseña
    const hashedPassword = bcryptjs.hashSync(password, 10);
    // Creación de un nuevo usuario
    const newUser = new User({
        username,
        lastname,
        email,
        password: hashedPassword,
    });
};`

Código generado por IA. Revisar y usar cuidadosamente. [Más información sobre preguntas frecuentes](https://www.bing.com/new#faq).

**Análisis Técnico:**

- **Validaciones:** Se realizan comprobaciones iniciales para errores de validación utilizando **`validationResult(req)`**.
- **Errores de Validación:** Si se encuentran errores, se retorna una respuesta con estado HTTP 422 y un array de errores.
- **Extracción de Datos:** Se extraen datos del cuerpo de la solicitud, incluyendo nombre de usuario, apellido, correo electrónico y contraseña.
- **Validaciones Adicionales:** Se asegura que ninguno de los campos esté vacío.
- **Hash de Contraseña:** Se utiliza **`bcryptjs`** para crear un hash seguro de la contraseña antes de almacenarla en la base de datos.
- **Creación de Usuario:** Se crea un nuevo objeto de usuario con los datos procesados y se almacena en la base de datos.

**Observaciones de Seguridad:**

- **Manejo de Contraseñas:** El uso de **`bcryptjs`** para el hash de contraseñas es una práctica segura para proteger las credenciales de los usuarios.
- **Validación de Campos:** Las validaciones adicionales ayudan a asegurar que todos los campos necesarios para el registro estén presentes y sean válidos.
