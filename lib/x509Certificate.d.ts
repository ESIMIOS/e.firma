import { asn1, pki } from "node-forge";
interface x509Subject {
    attributes: pki.CertificateField[];
    hash: unknown;
}
export declare class x509Certificate {
    asn1Object: asn1.Asn1;
    certificate: pki.Certificate;
    certificateType: "UNKNOW" | "CSD" | "EFIRMA";
    serialNumber: string;
    acVersion: number;
    valid: boolean;
    sha256: string;
    subjectType: "UNKNOW" | "MORAL" | "FISICA";
    constructor(x509Binary: string);
    static getSubjectField(subject: x509Subject, type: string, valueToFind: string): string | Array<string>;
    getBinary(): string;
    private certificateFromAsn1;
    getCertiticateType(): "UNKNOW" | "CSD" | "EFIRMA";
    getSubjectType(): "UNKNOW" | "MORAL" | "FISICA";
    verifyIntegrity(x509IssuerBinary: string): boolean;
    rsaEncrypt(message: string): any;
    rsaVerifySignature(message: string, signature: string, algorithm?: string, encoding?: "utf8"): boolean;
    getPEM(): string;
}
export {};
