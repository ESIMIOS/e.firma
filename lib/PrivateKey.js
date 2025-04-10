"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateKey = void 0;
const node_forge_1 = require("node-forge");
const GlobalMethods_1 = require("./GlobalMethods");
const ERROR_GENERAL_ERROR_1 = __importDefault(require("./errors/ERROR_GENERAL_ERROR"));
class PrivateKey {
    constructor(x509Binary) {
        this.encryptedPrivateKeyValidator = {
            tagClass: node_forge_1.asn1.Class.UNIVERSAL,
            type: node_forge_1.asn1.Type.SEQUENCE,
            constructed: true,
            value: [
                {
                    tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                    type: node_forge_1.asn1.Type.SEQUENCE,
                    constructed: true,
                    value: [
                        {
                            tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                            type: node_forge_1.asn1.Type.OID,
                            constructed: false,
                        },
                        {
                            tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                            type: node_forge_1.asn1.Type.SEQUENCE,
                            constructed: true,
                            value: [
                                {
                                    tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                                    type: node_forge_1.asn1.Type.SEQUENCE,
                                    constructed: true,
                                    value: [
                                        {
                                            tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                                            type: node_forge_1.asn1.Type.OID,
                                            constructed: false,
                                        },
                                        {
                                            tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                                            type: node_forge_1.asn1.Type.SEQUENCE,
                                            constructed: true,
                                            value: [
                                                {
                                                    tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                                                    type: node_forge_1.asn1.Type.OCTETSTRING,
                                                    constructed: false,
                                                },
                                                {
                                                    tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                                                    type: node_forge_1.asn1.Type.INTEGER,
                                                    constructed: false,
                                                },
                                            ],
                                        },
                                    ],
                                },
                                {
                                    tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                                    type: node_forge_1.asn1.Type.SEQUENCE,
                                    constructed: true,
                                    value: [
                                        {
                                            tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                                            type: node_forge_1.asn1.Type.OID,
                                            constructed: false,
                                        },
                                        {
                                            tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                                            type: node_forge_1.asn1.Type.OCTETSTRING,
                                            constructed: false,
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
                {
                    tagClass: node_forge_1.asn1.Class.UNIVERSAL,
                    type: node_forge_1.asn1.Type.OCTETSTRING,
                    constructed: false,
                },
            ],
        };
        this.asn1Object = GlobalMethods_1.GlobalMethods.readASN1(x509Binary);
        let errors = [];
        const isEncrypted = node_forge_1.asn1["validate"](this.asn1Object, this.encryptedPrivateKeyValidator, null, errors);
        if (!isEncrypted) {
            const message = `Llave privada no válida \n${errors.join("\n")}`;
            throw new ERROR_GENERAL_ERROR_1.default(message);
        }
    }
    rsaDecrypt(encryptedText, passwordKey) {
        const privateKeyInfo = node_forge_1.pki.decryptPrivateKeyInfo(this.asn1Object, passwordKey);
        const pem = node_forge_1.pki.privateKeyInfoToPem(privateKeyInfo);
        const privateKey = node_forge_1.pki.privateKeyFromPem(pem);
        const plainText = privateKey.decrypt(encryptedText);
        return plainText;
    }
    rsaSign(message, passwordKey, encoding) {
        const privateKeyInfo = node_forge_1.pki.decryptPrivateKeyInfo(this.asn1Object, passwordKey);
        const pem = node_forge_1.pki.privateKeyInfoToPem(privateKeyInfo);
        const privateKey = node_forge_1.pki.privateKeyFromPem(pem);
        const messageHash = GlobalMethods_1.GlobalMethods.hash(message, "sha256", true, encoding);
        console.log("mnessageHash", messageHash);
        const signature = privateKey.sign(messageHash);
        return signature;
    }
}
exports.PrivateKey = PrivateKey;
//# sourceMappingURL=PrivateKey.js.map