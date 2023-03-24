import { asn1, pki } from 'node-forge';
export declare class x509Certificate {
    ans1Object: asn1.Asn1;
    certificate: pki.Certificate;
    certificateType: string;
    serialNumber: string;
    acVersion: number;
    valid: boolean;
    sha256: string;
    constructor(x509Binary: string);
    getBinary(): string;
    private certificateFromAns1;
    getCertiticateType(): "EFIRMA" | "CSD" | "UNKNOW";
    verifyIntegrity(x509IssuerBinary: string): boolean;
    rsaEncrypt(message: string): any;
    rsaVerifySignature(message: string, signature: string, algorithm?: string, encoding?: 'utf8'): boolean;
    getPEM(): string;
}
//# sourceMappingURL=x509Certificate.d.ts.map