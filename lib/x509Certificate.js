"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.x509Certificate = void 0;
const node_forge_1 = require("node-forge");
const GlobalMethods_1 = require("./GlobalMethods");
const ERROR_GENERAL_ERROR_1 = __importDefault(require("./errors/ERROR_GENERAL_ERROR"));
class x509Certificate {
    constructor(x509Binary) {
        this.ans1Object = GlobalMethods_1.GlobalMethods.readASN1(x509Binary);
        const certificate = this.certificateFromAns1(this.ans1Object);
        this.serialNumber = certificate.serialNumber;
        this.acVersion = Number(this.serialNumber[23]);
        this.certificate = certificate;
        this.certificateType = this.getCertiticateType();
        this.sha256 = GlobalMethods_1.GlobalMethods.hash(x509Binary, 'sha256');
        const now = new Date();
        if (now < certificate.validity.notAfter && now > certificate.validity.notBefore) {
            this.valid = true;
        }
        else {
            this.valid = false;
        }
    }
    getBinary() {
        return node_forge_1.asn1.toDer(this.ans1Object).getBytes();
    }
    certificateFromAns1(ans1Object) {
        try {
            const certificate = node_forge_1.pki.certificateFromAsn1(ans1Object);
            return certificate;
        }
        catch (err) {
            throw new ERROR_GENERAL_ERROR_1.default('Verifique el archivo, no fue posible convertir el ANS1 a certificado');
        }
    }
    getCertiticateType() {
        const extensions = this.certificate.extensions;
        for (let i in extensions) {
            if (extensions[i].name === 'extKeyUsage' && extensions[i].emailProtection === true && extensions[i].clientAuth === true) {
                return 'EFIRMA';
            }
            if (extensions[i].name === 'keyUsage' && extensions[i].digitalSignature === true && extensions[i].nonRepudiation === true && extensions[i].dataEncipherment === false && extensions[i].keyAgreement === false) {
                return 'CSD';
            }
        }
        return 'UNKNOW';
    }
    verifyIntegrity(x509IssuerBinary) {
        const issuerCertificate = GlobalMethods_1.GlobalMethods.readASN1(x509IssuerBinary);
        const certificate = this.certificateFromAns1(issuerCertificate);
        try {
            const isValid = certificate.verify(this.certificate);
            return isValid;
        }
        catch (err) {
            if (err instanceof Error) {
                if (err.message.toString().indexOf('The parent certificate did not issue') >= 0) {
                    throw new ERROR_GENERAL_ERROR_1.default('El certificado del issuer recibido no es el de este certificado');
                }
            }
            throw err;
        }
    }
    rsaEncrypt(message) {
        const encrypted = this.certificate.publicKey['encrypt'](message);
        return encrypted;
    }
    rsaVerifySignature(message, signature, algorithm = 'sha256', encoding) {
        const messageHash = GlobalMethods_1.GlobalMethods.hash(message, algorithm, true, encoding);
        const messageDigest = messageHash.digest().bytes();
        const verified = this.certificate.publicKey['verify'](messageDigest, signature);
        return verified;
    }
    getPEM() {
        return node_forge_1.pki.certificateToPem(this.certificate);
    }
}
exports.x509Certificate = x509Certificate;
//# sourceMappingURL=x509Certificate.js.map