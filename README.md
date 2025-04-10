# e.firma 
Paquete para manejar firmas RSA con validación OCSP y verificación de autenticidad de certificados X509 

## Descripción
Este paquete proporciona una solución completa para el manejo de certificados digitales y firmas electrónicas, con especial énfasis en la validación OCSP (Online Certificate Status Protocol) y la verificación de certificados X509. Es especialmente útil para aplicaciones que requieren manejo de certificados digitales del SAT (Servicio de Administración Tributaria) de México.

## Características Principales

### Clase x509Certificate
- Validación de certificados X509
- Soporte para certificados CSD y EFIRMA
- Verificación de validez temporal (expiración)
- Encriptación RSA de mensajes
- Verificación de firmas RSA
- Verificación de integridad de certificados
- Soporte para certificados AC4 y AC5 del SAT
- Identificación de tipo de sujeto (MORAL/FISICA)
- Conversión a formato PEM

### Clase Ocsp
- Validación de estado de certificados mediante OCSP
- Soporte para respuestas GOOD, REVOKED y TRYLATER
- Verificación de firmas de respuestas OCSP
- Manejo de fechas de revocación
- Validación de URLs de servicios OCSP

### Clase PrivateKey
- Manejo de llaves privadas RSA
- Soporte para llaves encriptadas y desencriptadas
- Validación de formato de llaves privadas
- Encriptación y desencriptación de mensajes
- Generación de firmas digitales

## Diagrama de Clases
![Descripción del SVG](out.svg)

## Instalación
```bash
npm install e.firma
```

## Uso Básico

### Validación de Certificado
```typescript
import { x509Certificate } from 'e.firma';
import * as fs from 'fs';

// Cargar certificado desde archivo
const certificateFile = fs.readFileSync('ruta/al/certificado.cer', 'binary');
const cert = new x509Certificate(certificateFile);

// Verificar tipo de certificado
console.log(cert.certificateType); // 'CSD' o 'EFIRMA'

// Verificar validez temporal
console.log(cert.valid); // true/false

// Verificar tipo de sujeto
console.log(cert.subjectType); // 'MORAL' o 'FISICA'

// Obtener número de serie
console.log(cert.serialNumber);

// Obtener versión AC
console.log(cert.acVersion); // 4 o 5

// Convertir a formato PEM
const pemFormat = cert.getPEM();
```

### Verificación de Integridad de Certificado
```typescript
import { x509Certificate } from 'e.firma';
import * as fs from 'fs';

// Cargar certificado a verificar
const subjectCert = new x509Certificate(fs.readFileSync('certificado.cer', 'binary'));

// Cargar certificado emisor (AC4 o AC5 del SAT)
const issuerCert = new x509Certificate(fs.readFileSync('AC5_SAT.cer', 'binary'));

// Verificar integridad
const isValid = subjectCert.verifyIntegrity(issuerCert);
console.log('Certificado válido:', isValid);
```

### Verificación OCSP
```typescript
import { Ocsp } from 'e.firma';
import * as fs from 'fs';

// Cargar certificados necesarios
const subjectCert = new x509Certificate(fs.readFileSync('certificado.cer', 'binary'));
const issuerCert = new x509Certificate(fs.readFileSync('AC5_SAT.cer', 'binary'));
const ocspCert = new x509Certificate(fs.readFileSync('ocsp.ac5_sat.cer', 'binary'));

// Crear instancia de OCSP
const ocsp = new Ocsp(
    'https://cfdi.sat.gob.mx/edofiel',
    issuerCert,
    subjectCert,
    ocspCert
);

// Verificar estado del certificado
try {
    const response = await ocsp.verify();
    console.log('Estado:', response.status); // 'GOOD', 'REVOKED', etc.
    
    if (response.status === 'REVOKED') {
        console.log('Fecha de revocación:', response.revocationTime);
    }
} catch (error) {
    console.error('Error en verificación OCSP:', error.message);
}
```

### Manejo de Llaves Privadas
```typescript
import { PrivateKey } from 'e.firma';
import * as fs from 'fs';

// Cargar llave privada
const keyFile = fs.readFileSync('ruta/a/llave.key', 'binary');
const privateKey = new PrivateKey(keyFile);

// Encriptar mensaje
const message = 'Mensaje a encriptar';
const encryptedMessage = privateKey.rsaEncrypt(message);

// Desencriptar mensaje
const decryptedMessage = privateKey.rsaDecrypt(encryptedMessage, 'contraseña');

// Firmar mensaje
const signature = privateKey.rsaSign(message, 'contraseña');

// Verificar firma con certificado
const cert = new x509Certificate(fs.readFileSync('certificado.cer', 'binary'));
const isValidSignature = cert.rsaVerifySignature(message, signature);
```

### Encriptación y Verificación de Mensajes
```typescript
import { x509Certificate } from 'e.firma';
import { PrivateKey } from 'e.firma';
import * as fs from 'fs';

// Cargar certificado y llave privada
const cert = new x509Certificate(fs.readFileSync('certificado.cer', 'binary'));
const privateKey = new PrivateKey(fs.readFileSync('llave.key', 'binary'));

// Encriptar mensaje con certificado público
const message = 'Mensaje secreto';
const encryptedMessage = cert.rsaEncrypt(message);

// Desencriptar mensaje con llave privada
const decryptedMessage = privateKey.rsaDecrypt(encryptedMessage, 'contraseña');

// Verificar que el mensaje coincide
console.log('Mensaje original:', message);
console.log('Mensaje desencriptado:', decryptedMessage);
```

## Manejo de Errores
El paquete incluye manejo de errores específicos para diferentes situaciones:

```typescript
try {
    // Operaciones con certificados o llaves
} catch (error) {
    if (error.message.includes('Verifique el archivo')) {
        console.error('Error en formato de archivo');
    } else if (error.message.includes('El certificado recibido no fue emitido')) {
        console.error('Error en verificación de emisor');
    } else if (error.message.includes('Error al consultar el servicio')) {
        console.error('Error en servicio OCSP');
    }
}
```

## Licencia
MIT

