/// <reference types="node" />
import { asn1 } from 'node-forge';
import { x509Certificate } from './x509Certificate';
export declare enum OCSP_REQUEST_STATUS {
    SUCCESSFUL = "00",
    MALFORMEDREQUEST = "01",
    INTERNALERROR = "02",
    TRYLATER = "03",
    UNDEFINED = "",
    SIGREQUIRED = "05",
    UNAUTHORIZED = "06"
}
export declare enum OCSP_CERTIFICATE_STATUS {
    GOOD = 0,
    REVOKED = 1,
    UNKNOW = 2
}
export type ocspResponseVerify = {
    status: string;
};
export interface certificateStatusVerify extends ocspResponseVerify {
    revocationTime?: Date;
}
export interface verifyResponse extends certificateStatusVerify {
    ocspRequestBinary?: string;
    ocspResponseBinary?: string;
}
export declare class Ocsp {
    private issuerCertificate;
    private subjectCertificate;
    private ocspCertificate;
    private urlService;
    constructor(urlService: string, issuerCertificate: x509Certificate, subjectCertificate: x509Certificate, ocspCertificate: x509Certificate);
    private getOCSPRequest;
    callToService(body: Buffer): Promise<Blob>;
    private dateFromANS1Date;
    verifyOcspResponseSignature(asn1GoodOCSPBasic: asn1.Asn1): boolean;
    verifyOcspResponse(asn1OcspResponse: asn1.Asn1): ocspResponseVerify;
    verifyCertificateStatus(asn1OCSPBasic: asn1.Asn1): certificateStatusVerify;
    verify(): Promise<verifyResponse>;
    private getIssuerNameBinary;
    private getASN1PublicKeyBinary;
}
//# sourceMappingURL=Ocsp.d.ts.map