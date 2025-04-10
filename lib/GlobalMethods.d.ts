import { asn1 } from "node-forge";
export declare class GlobalMethods {
    constructor();
    static hash(input: string, algorithm?: string, returnForgeHashObject?: boolean, encoding?: "utf8" | ""): any;
    static readASN1(file: string): asn1.Asn1;
    static binaryToBase64(binary: string): string;
    static base64ToBinary(base64String: string): string;
}
