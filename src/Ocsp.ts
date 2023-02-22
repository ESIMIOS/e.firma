import { asn1, pki, md, util } from 'node-forge'
import { x509Certificate } from './x509Certificate'
import fetch from 'cross-fetch'
import { GlobalMethods } from './GlobalMethods'
import ERROR_GENERAL_ERROR from './errors/ERROR_GENERAL_ERROR'
export enum OCSP_REQUEST_STATUS {
	SUCCESSFUL = '00',
	MALFORMEDREQUEST = '01',
	INTERNALERROR = '02',
	TRYLATER = '03',
	UNDEFINED = '',
	SIGREQUIRED = '05',
	UNAUTHORIZED = '06'
}

export enum OCSP_CERTIFICATE_STATUS {
	GOOD = 0,
	REVOKED = 1,
	UNKNOW = 2
}
export type ocspResponseVerify = {
	status: string
}

export interface certificateStatusVerify extends ocspResponseVerify {
	revocationTime?: Date
}

export interface verifyResponse extends certificateStatusVerify {
	ocspRequestBinary?: string
	ocspResponseBinary?: string
}

export class Ocsp {
	private issuerCertificate: x509Certificate
	private subjectCertificate: x509Certificate
	private ocspCertificate: x509Certificate
	private urlService: string
	constructor(urlService: string, issuerCertificate: x509Certificate, subjectCertificate: x509Certificate, ocspCertificate: x509Certificate) {
		this.issuerCertificate = issuerCertificate
		this.subjectCertificate = subjectCertificate
		this.ocspCertificate = ocspCertificate
		const regexUrl = /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/im
		if (!regexUrl.test(urlService)) {
			throw new ERROR_GENERAL_ERROR('Revisar la url del servicio OCSP, el formato no es de URL')
		}
		this.urlService = urlService
	}

	private getOCSPRequest(): util.ByteBuffer {
		const issuerNameBinary = this.getIssuerNameBinary()
		const hashIssuerNameBinary = GlobalMethods.hash(issuerNameBinary, 'sha1')
		const issuerNameHash = Buffer.from(hashIssuerNameBinary, 'hex').toString('binary')

		const publicKeyFromANS1 = this.getASN1PublicKeyBinary()
		const hashPublicKeyFromANS1 = GlobalMethods.hash(publicKeyFromANS1, 'sha1')
		const issuerKeyHash = Buffer.from(hashPublicKeyFromANS1, 'hex').toString('binary')

		const serialNumber = Buffer.from(this.subjectCertificate.serialNumber, 'hex').toString('binary')

		const ans1OCSPRequest = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
			asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
				asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
					asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
						asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
							asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(pki.oids['sha1']).getBytes()), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')]),
							asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, issuerNameHash),
							asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, issuerKeyHash),
							asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, serialNumber)
						])
					])
				]),
				asn1.create(asn1.Class.CONTEXT_SPECIFIC, asn1.Type.INTEGER, true, [
					asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
						asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
							asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer('1.3.6.1.5.5.7.48.1.2').getBytes()),
							//@ts-ignore
							asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, Buffer.from('041064bb982b0f6236984ec9d8c4997b6996', 'hex'))
						])
					])
				])
			])
		])
		const ocspRequestDer = asn1.toDer(ans1OCSPRequest)
		//@ts-ignore
		return ocspRequestDer
	}

	async callToService(body: Buffer): Promise<Blob> {
		console.log('callToService', this.urlService)
		const response = await fetch(this.urlService, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/octet-stream'
			},
			body: body
		})
		if (response.status != 200) {
			throw new ERROR_GENERAL_ERROR('Error al consultar el servicio ' + this.urlService)
		}
		const blob = await response.blob()
		//@ts-ignore
		return blob
	}

	private dateFromANS1Date(date: string): Date {
		if (date.indexOf('Z') == -1) {
			throw new ERROR_GENERAL_ERROR('Formato de fecha incorrecto, se espera YYYYMMDDHHMMSSZ')
		}
		return new Date(date.slice(0, 4) + '-' + date.slice(4, 6) + '-' + date.slice(6, 8) + 'T' + date.slice(8, 10) + ':' + date.slice(10, 12) + ':' + date.slice(12, 14) + '.000' + date.slice(14, 15))
	}

	verifyOcspResponseSignature(asn1GoodOCSPBasic: asn1.Asn1): boolean {
		try {
			//@ts-ignore
			const signatureBinary: string = asn1GoodOCSPBasic.value[2]['value']
			const signature = signatureBinary.slice(1, signatureBinary.length)
			//@ts-ignore
			const asn1Value: asn1.Asn1[] = asn1GoodOCSPBasic.value[0]['value']
			const tbsRespobseDataAsn1 = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, asn1Value)
			const tbsRespobseDataDer = asn1.toDer(tbsRespobseDataAsn1)
			const tbsRespobseData = tbsRespobseDataDer.getBytes()
			const verifiedSignature = this.ocspCertificate.rsaVerifySignature(tbsRespobseData, signature, 'sha1')
			return verifiedSignature
		} catch (err) {
			if (err instanceof Error) {
				if (err.message.indexOf('Encryption block is invalid') >= 0) {
					return false
				}
			}
			throw err
		}
	}

	verifyOcspResponse(asn1OcspResponse: asn1.Asn1): ocspResponseVerify {
		//@ts-ignore
		const ocspResponseStatus = Buffer.from(asn1OcspResponse.value[0]['value']).toString('hex')
		if (ocspResponseStatus == OCSP_REQUEST_STATUS.SUCCESSFUL) {
			return { status: OCSP_REQUEST_STATUS.SUCCESSFUL }
		} else if (ocspResponseStatus == OCSP_REQUEST_STATUS.TRYLATER) {
			return { status: OCSP_REQUEST_STATUS.TRYLATER }
		} else {
			return { status: OCSP_REQUEST_STATUS.UNDEFINED }
		}
	}

	verifyCertificateStatus(asn1OCSPBasic: asn1.Asn1): certificateStatusVerify {
		//@ts-ignore
		const certificateStatus = asn1OCSPBasic.value[0]['value'][2].value[0].value[1]
		if (certificateStatus.type === OCSP_CERTIFICATE_STATUS.GOOD) {
			return { status: 'GOOD' }
		} else if (certificateStatus.type === OCSP_CERTIFICATE_STATUS.REVOKED) {
			const revocationTime = this.dateFromANS1Date(certificateStatus.value[0].value)
			return { status: 'REVOKED', revocationTime }
		} else if (certificateStatus.type === OCSP_CERTIFICATE_STATUS.UNKNOW) {
			return { status: 'UNKNOW' }
		} else {
			return { status: 'UNDEFINED' }
		}
	}

	async verify(): Promise<verifyResponse> {
		const ocspRequest = this.getOCSPRequest()
		const originalData = Buffer.from(ocspRequest.getBytes(), 'binary')
		const ocspResponseBlob = await this.callToService(originalData)
		const arrayBuffer = await ocspResponseBlob.arrayBuffer()
		const ocspResponseBinary = Buffer.from(arrayBuffer).toString('binary')
		const asn1OcspResponse = asn1.fromDer(ocspResponseBinary)
		const ocspResponseStatus = this.verifyOcspResponse(asn1OcspResponse)
		if (ocspResponseStatus.status === OCSP_REQUEST_STATUS.SUCCESSFUL) {
			//@ts-ignore
			const asn1OCSPBasic = asn1.fromDer(asn1OcspResponse.value[1]['value'][0].value[1].value)
			const verify = this.verifyOcspResponseSignature(asn1OCSPBasic)
			if (verify) {
				const certificateStatus = this.verifyCertificateStatus(asn1OCSPBasic)
				return {
					...certificateStatus,
					ocspRequestBinary: originalData.toString('binary'),
					ocspResponseBinary
				}
			} else {
				throw new ERROR_GENERAL_ERROR('La firma de la respuesta OCSP no corresponde')
			}
		} else {
			throw new ERROR_GENERAL_ERROR('No fue posible realizar la validación OCSP \n' + ocspResponseStatus)
		}
	}

	private getIssuerNameBinary(): string {
		const attrs = this.subjectCertificate.certificate.issuer.attributes
		const items: asn1.Asn1[] = []
		const createBlock = (oid: string, value: any, type: number) => {
			type = type || asn1.Type.UTF8
			return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oid).getBytes()), asn1.create(asn1.Class.UNIVERSAL, type, false, value)])])
		}
		attrs.forEach((attr) => {
			//@ts-ignore
			items.push(createBlock(attr.type, attr.value, attr.valueTagClass))
		})
		const DN = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, items)
		const der = asn1.toDer(DN)
		const bytes = der.getBytes()
		return bytes
	}

	private getASN1PublicKeyBinary(): string {
		const asn1IssuerCert = this.issuerCertificate.ans1Object
		//@ts-ignore
		const publicKeyAsn1Node = asn1IssuerCert.value[0].value[6].value[1].bitStringContents
		const ocspIssuerPublicKey = publicKeyAsn1Node.slice(1, publicKeyAsn1Node.length)
		const ocspIssuerPublicKeyBinary = ocspIssuerPublicKey.toString('binary')
		return ocspIssuerPublicKeyBinary
	}
}
