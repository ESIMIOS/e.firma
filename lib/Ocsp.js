"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Ocsp = exports.OCSP_CERTIFICATE_STATUS = exports.OCSP_REQUEST_STATUS = void 0;
const node_forge_1 = require("node-forge");
const cross_fetch_1 = __importDefault(require("cross-fetch"));
const GlobalMethods_1 = require("./GlobalMethods");
const ERROR_GENERAL_ERROR_1 = __importDefault(require("./errors/ERROR_GENERAL_ERROR"));
var OCSP_REQUEST_STATUS;
(function (OCSP_REQUEST_STATUS) {
    OCSP_REQUEST_STATUS["SUCCESSFUL"] = "00";
    OCSP_REQUEST_STATUS["MALFORMEDREQUEST"] = "01";
    OCSP_REQUEST_STATUS["INTERNALERROR"] = "02";
    OCSP_REQUEST_STATUS["TRYLATER"] = "03";
    OCSP_REQUEST_STATUS["UNDEFINED"] = "";
    OCSP_REQUEST_STATUS["SIGREQUIRED"] = "05";
    OCSP_REQUEST_STATUS["UNAUTHORIZED"] = "06";
})(OCSP_REQUEST_STATUS || (exports.OCSP_REQUEST_STATUS = OCSP_REQUEST_STATUS = {}));
var OCSP_CERTIFICATE_STATUS;
(function (OCSP_CERTIFICATE_STATUS) {
    OCSP_CERTIFICATE_STATUS[OCSP_CERTIFICATE_STATUS["GOOD"] = 0] = "GOOD";
    OCSP_CERTIFICATE_STATUS[OCSP_CERTIFICATE_STATUS["REVOKED"] = 1] = "REVOKED";
    OCSP_CERTIFICATE_STATUS[OCSP_CERTIFICATE_STATUS["UNKNOW"] = 2] = "UNKNOW";
})(OCSP_CERTIFICATE_STATUS || (exports.OCSP_CERTIFICATE_STATUS = OCSP_CERTIFICATE_STATUS = {}));
class Ocsp {
    constructor(urlService, issuerCertificate, subjectCertificate, ocspCertificate) {
        this.issuerCertificate = issuerCertificate;
        this.subjectCertificate = subjectCertificate;
        this.ocspCertificate = ocspCertificate;
        const regexUrl = /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/im;
        if (!regexUrl.test(urlService)) {
            throw new ERROR_GENERAL_ERROR_1.default("Revisar la url del servicio OCSP, el formato no es de URL");
        }
        this.urlService = urlService;
    }
    getOCSPRequest() {
        const issuerNameBinary = this.getIssuerNameBinary();
        const hashIssuerNameBinary = GlobalMethods_1.GlobalMethods.hash(issuerNameBinary, "sha1");
        const issuerNameHash = Buffer.from(hashIssuerNameBinary, "hex").toString("binary");
        const publicKeyFromASN1 = this.getASN1PublicKeyBinary();
        const hashPublicKeyFromASN1 = GlobalMethods_1.GlobalMethods.hash(publicKeyFromASN1, "sha1");
        const issuerKeyHash = Buffer.from(hashPublicKeyFromASN1, "hex").toString("binary");
        const serialNumber = Buffer.from(this.subjectCertificate.serialNumber, "hex").toString("binary");
        const asn1OCSPRequest = node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
            node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
                node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
                    node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
                        node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
                            node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
                                node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.OID, false, node_forge_1.asn1.oidToDer(node_forge_1.pki.oids["sha1"]).getBytes()),
                                node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.NULL, false, ""),
                            ]),
                            node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.OCTETSTRING, false, issuerNameHash),
                            node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.OCTETSTRING, false, issuerKeyHash),
                            node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.INTEGER, false, serialNumber),
                        ]),
                    ]),
                ]),
                node_forge_1.asn1.create(node_forge_1.asn1.Class.CONTEXT_SPECIFIC, node_forge_1.asn1.Type.INTEGER, true, [
                    node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
                        node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
                            node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.OID, false, node_forge_1.asn1.oidToDer("1.3.6.1.5.5.7.48.1.2").getBytes()),
                            node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.OCTETSTRING, false, Buffer.from("041064bb982b0f6236984ec9d8c4997b6996", "hex").toString("binary")),
                        ]),
                    ]),
                ]),
            ]),
        ]);
        const ocspRequestDer = node_forge_1.asn1.toDer(asn1OCSPRequest);
        return ocspRequestDer;
    }
    callToService(body) {
        return __awaiter(this, void 0, void 0, function* () {
            console.log("callToService", this.urlService);
            const response = yield (0, cross_fetch_1.default)(this.urlService, {
                method: "POST",
                headers: {
                    "Content-Type": "application/octet-stream",
                },
                body: body,
            });
            if (response.status != 200) {
                throw new ERROR_GENERAL_ERROR_1.default("Error al consultar el servicio " + this.urlService);
            }
            const blob = yield response.blob();
            return blob;
        });
    }
    dateFromASN1Date(date) {
        if (date.indexOf("Z") == -1) {
            throw new ERROR_GENERAL_ERROR_1.default("Formato de fecha incorrecto, se espera YYYYMMDDHHMMSSZ");
        }
        return new Date(date.slice(0, 4) +
            "-" +
            date.slice(4, 6) +
            "-" +
            date.slice(6, 8) +
            "T" +
            date.slice(8, 10) +
            ":" +
            date.slice(10, 12) +
            ":" +
            date.slice(12, 14) +
            ".000" +
            date.slice(14, 15));
    }
    verifyOcspResponseSignature(asn1GoodOCSPBasic) {
        try {
            const signatureBinary = asn1GoodOCSPBasic.value[2]["value"];
            const signature = signatureBinary.slice(1, signatureBinary.length);
            const asn1Value = asn1GoodOCSPBasic.value[0]["value"];
            const tbsRespobseDataAsn1 = node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, asn1Value);
            const tbsRespobseDataDer = node_forge_1.asn1.toDer(tbsRespobseDataAsn1);
            const tbsRespobseData = tbsRespobseDataDer.getBytes();
            const verifiedSignature = this.ocspCertificate.rsaVerifySignature(tbsRespobseData, signature, "sha1");
            return verifiedSignature;
        }
        catch (err) {
            if (err instanceof Error) {
                if (err.message.indexOf("Encryption block is invalid") >= 0) {
                    return false;
                }
            }
            throw err;
        }
    }
    verifyOcspResponse(asn1OcspResponse) {
        const ocspResponseStatus = Buffer.from(asn1OcspResponse.value[0]["value"]).toString("hex");
        if (ocspResponseStatus == OCSP_REQUEST_STATUS.SUCCESSFUL) {
            return { status: OCSP_REQUEST_STATUS.SUCCESSFUL };
        }
        else if (ocspResponseStatus == OCSP_REQUEST_STATUS.TRYLATER) {
            return { status: OCSP_REQUEST_STATUS.TRYLATER };
        }
        else {
            return { status: OCSP_REQUEST_STATUS.UNDEFINED };
        }
    }
    verifyCertificateStatus(asn1OCSPBasic) {
        const certificateStatus = asn1OCSPBasic.value[0]["value"][2]
            .value[0].value[1];
        if (certificateStatus.type === OCSP_CERTIFICATE_STATUS.GOOD) {
            return { status: "GOOD" };
        }
        else if (certificateStatus.type === OCSP_CERTIFICATE_STATUS.REVOKED) {
            const revocationTime = this.dateFromASN1Date(certificateStatus.value[0].value);
            return { status: "REVOKED", revocationTime };
        }
        else if (certificateStatus.type === OCSP_CERTIFICATE_STATUS.UNKNOW) {
            return { status: "UNKNOW" };
        }
        else {
            return { status: "UNDEFINED" };
        }
    }
    verify() {
        return __awaiter(this, void 0, void 0, function* () {
            const ocspRequest = this.getOCSPRequest();
            const originalData = Buffer.from(ocspRequest.getBytes(), "binary");
            const ocspResponseBlob = yield this.callToService(originalData);
            const arrayBuffer = yield ocspResponseBlob.arrayBuffer();
            const ocspResponseBinary = Buffer.from(arrayBuffer).toString("binary");
            const asn1OcspResponse = node_forge_1.asn1.fromDer(ocspResponseBinary);
            const ocspResponseStatus = this.verifyOcspResponse(asn1OcspResponse);
            if (ocspResponseStatus.status === OCSP_REQUEST_STATUS.SUCCESSFUL) {
                const asn1OCSPBasic = node_forge_1.asn1.fromDer(asn1OcspResponse.value[1]["value"][0].value[1].value);
                const verify = this.verifyOcspResponseSignature(asn1OCSPBasic);
                if (verify) {
                    const certificateStatus = this.verifyCertificateStatus(asn1OCSPBasic);
                    return Object.assign(Object.assign({}, certificateStatus), { ocspRequestBinary: originalData.toString("binary"), ocspResponseBinary });
                }
                else {
                    throw new ERROR_GENERAL_ERROR_1.default("La firma de la respuesta OCSP no corresponde");
                }
            }
            else {
                throw new ERROR_GENERAL_ERROR_1.default("No fue posible realizar la validación OCSP \n" + ocspResponseStatus);
            }
        });
    }
    getIssuerNameBinary() {
        const attrs = this.subjectCertificate.certificate.issuer.attributes;
        const items = [];
        const createBlock = (oid, value, type) => {
            type = type || node_forge_1.asn1.Type.UTF8;
            return node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SET, true, [
                node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, [
                    node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.OID, false, node_forge_1.asn1.oidToDer(oid).getBytes()),
                    node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, type, false, value),
                ]),
            ]);
        };
        attrs.forEach((attr) => {
            items.push(createBlock(attr.type, attr.value, attr.valueTagClass));
        });
        const DN = node_forge_1.asn1.create(node_forge_1.asn1.Class.UNIVERSAL, node_forge_1.asn1.Type.SEQUENCE, true, items);
        const der = node_forge_1.asn1.toDer(DN);
        const bytes = der.getBytes();
        return bytes;
    }
    getASN1PublicKeyBinary() {
        const asn1IssuerCert = this.issuerCertificate.asn1Object;
        const publicKeyAsn1Node = asn1IssuerCert.value[0].value[6].value[1].bitStringContents;
        const ocspIssuerPublicKey = publicKeyAsn1Node.slice(1, publicKeyAsn1Node.length);
        const ocspIssuerPublicKeyBinary = ocspIssuerPublicKey.toString("binary");
        return ocspIssuerPublicKeyBinary;
    }
}
exports.Ocsp = Ocsp;
//# sourceMappingURL=Ocsp.js.map