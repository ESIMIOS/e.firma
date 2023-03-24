export declare class PrivateKey {
    private ans1Object;
    private encryptedPrivateKeyValidator;
    constructor(x509Binary: string);
    rsaDecrypt(encryptedText: string, passwordKey: string): string;
    rsaSign(message: string, passwordKey: string, encoding?: 'utf8'): string;
}
