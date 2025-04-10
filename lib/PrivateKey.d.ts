export declare class PrivateKey {
    private readonly asn1Object;
    private readonly encryptedPrivateKeyValidator;
    constructor(x509Binary: string);
    rsaDecrypt(encryptedText: string, passwordKey: string): string;
    rsaSign(message: string, passwordKey: string, encoding?: "utf8"): string;
}
