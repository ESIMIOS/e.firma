import * as fs from 'fs'
import { asn1 } from 'node-forge'
import x509Certificate from './x509Certificate'
import PrivateKey from './PrivateKey'
import Ocsp from './Ocsp'
// const certificateFile = fs.readFileSync('../keys/TEST_CESAR/00001000000506724016.cer.bak', 'binary')
const certificateFile = fs.readFileSync('../keys/TEST_SAT/Personas Fisicas/FIEL_CACX7605101P8_20190528152826/cacx7605101p8.cer', 'binary')

// const certificateFile = fs.readFileSync('../keys/TEST_SAT/Personas Fisicas/FIEL_CACX7605101P8_20190528152826/CSD_CACX7605101P8_20190528173620/30001000000400002335.cer', 'binary')
// const certificateFileFromIssuer = fs.readFileSync('../certificates/SAT/AC5_SAT.cer', 'binary')

const certificate = new x509Certificate(certificateFile)
// const validCertificate = certificate.verifyIntegrity(certificateFileFromIssuer)

// console.log('validCertificate', validCertificate)

const privateKeyFile = fs.readFileSync('../keys/TEST_SAT/Personas Fisicas/FIEL_CACX7605101P8_20190528152826/Claveprivada_FIEL_CACX7605101P8_20190528_152826.key', 'binary')
const privateKey = new PrivateKey(privateKeyFile)

const encryptedMessage = certificate.rsaEncrypt('Hola')
const decryptedMessage = privateKey.rsaDecrypt(encryptedMessage, '12345678a')

console.log('decryptedMessage', decryptedMessage)
const messageForSignature = 'Mensaje firmado'
const signature = privateKey.rsaSign(messageForSignature, '12345678a')
console.log('signature', signature)

const verifySignature = certificate.rsaVerifySignature(messageForSignature, signature)
console.log('verifySignature', verifySignature)

//OCSP Call
console.log('\n\n-------------OCSP-------------------\n\n')
const issuerCertificateFile = fs.readFileSync('../certificates/SAT/AC5_SAT.cer', 'binary')
const issuerCertificate = new x509Certificate(issuerCertificateFile)

const ocspCertificateFile = fs.readFileSync('../certificates/SAT/ocsp.ac5_sat.cer', 'binary')
const ocspCertificate = new x509Certificate(ocspCertificateFile)

const ocspCertificateFile4 = fs.readFileSync('../certificates/SAT/ocsp.ac5_sat.cer', 'binary')
const ocspCertificate4 = new x509Certificate(ocspCertificateFile4)

const subjectCertificateFile = fs.readFileSync('../keys/TEST_CESAR/00001000000506724016.cer.bak', 'binary')
const subjectCertificate = new x509Certificate(subjectCertificateFile)

const ocsp = new Ocsp('https://cfdi.sat.gob.mx/edofi', issuerCertificate, subjectCertificate, ocspCertificate4)
const ocspResponseBinary = fs.readFileSync('../ocspResponses/revoked.der', 'binary')
const asn1OcspResponse = asn1.fromDer(ocspResponseBinary)
const asn1OCSPBasic = asn1.fromDer(asn1OcspResponse.value[1]['value'][0].value[1].value)
ocsp.verifyOcspResponse(asn1OcspResponse)
ocsp.verifyCertificateStatus(asn1OCSPBasic)
ocsp.verifyOcspResponseSignature(asn1OCSPBasic)

console.log('\n-----------------\n')
const ocspGood = new Ocsp('https://cfdi.sat.gob.mx/edofi', issuerCertificate, subjectCertificate, ocspCertificate)
const ocspResponseGoodBinary = fs.readFileSync('../ocspResponses/good.der', 'binary')
const asn1OcspGoodResponse = asn1.fromDer(ocspResponseGoodBinary)
ocsp.verifyOcspResponse(asn1OcspGoodResponse)
const asn1OCSGoodPBasic = asn1.fromDer(asn1OcspGoodResponse.value[1]['value'][0].value[1].value)
ocsp.verifyCertificateStatus(asn1OCSGoodPBasic)
ocsp.verifyOcspResponseSignature(asn1OCSGoodPBasic)
