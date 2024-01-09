import { asn1, pki } from 'node-forge'
import { GlobalMethods } from './GlobalMethods'
import ERROR_GENERAL_ERROR from './errors/ERROR_GENERAL_ERROR'

interface x509Subject {
	attributes: pki.CertificateField[]
	hash: unknown
}
export class x509Certificate {
	asn1Object: asn1.Asn1
	certificate: pki.Certificate
	certificateType: 'UNKNOW' | 'CSD' | 'EFIRMA'
	serialNumber: string
	acVersion: number
	valid: boolean
	sha256: string
	subjectType: 'UNKNOW' | 'MORAL' | 'FISICA'

	constructor(x509Binary: string) {
		this.asn1Object = GlobalMethods.readASN1(x509Binary)
		const certificate = this.certificateFromAsn1(this.asn1Object)
		this.serialNumber = certificate.serialNumber
		this.acVersion = Number(this.serialNumber[23])
		this.certificate = certificate
		this.certificateType = this.getCertiticateType()
		this.sha256 = GlobalMethods.hash(x509Binary, 'sha256')
		this.subjectType = this.getSubjectType()
		const now = new Date()
		if (now < certificate.validity.notAfter && now > certificate.validity.notBefore) {
			this.valid = true
		} else {
			this.valid = false
		}
	}

	public static getSubjectField(subject: x509Subject, type: string, valueToFind: string): string | Array<string> {
		let value: string | Array<string>
		if (subject && subject.attributes && Array.isArray(subject.attributes)) {
			//@ts-ignore
			const findResult = subject.attributes.find((field) => field[type] === valueToFind)
			if (findResult.value) {
				value = findResult.value
			}
		}
		if (!value) {
			throw new ERROR_GENERAL_ERROR(`${valueToFind} no encontrado en el tipo ${type}`)
		}
		return value
	}

	getBinary() {
		return asn1.toDer(this.asn1Object).getBytes()
	}

	private certificateFromAsn1(asn1Object: asn1.Asn1) {
		try {
			const certificate = pki.certificateFromAsn1(asn1Object)
			return certificate
		} catch (err) {
			throw new ERROR_GENERAL_ERROR('Verifique el archivo, no fue posible convertir el ASN1 a certificado')
		}
	}

	getCertiticateType() {
		const extensions = this.certificate.extensions
		for (let i in extensions) {
			if (extensions[i].name === 'extKeyUsage' && extensions[i].emailProtection === true && extensions[i].clientAuth === true) {
				return 'EFIRMA'
			}
			if (extensions[i].name === 'keyUsage' && extensions[i].digitalSignature === true && extensions[i].nonRepudiation === true && extensions[i].dataEncipherment === false && extensions[i].keyAgreement === false) {
				return 'CSD'
			}
		}
		return 'UNKNOW'
	}

	getSubjectType() {
		try {
			const subjectRfc = x509Certificate.getSubjectField(this.certificate.subject, 'type', '2.5.4.45')
			if (subjectRfc.indexOf(' / ') >= 0) {
				return 'MORAL'
			} else if (subjectRfc.length === 13) {
				return 'FISICA'
			}
		} catch (err) {
			console.warn(err)
		}

		return 'UNKNOW'
	}

	verifyIntegrity(x509IssuerBinary: string) {
		const issuerCertificate = GlobalMethods.readASN1(x509IssuerBinary)
		const certificate = this.certificateFromAsn1(issuerCertificate)
		try {
			const isValid = certificate.verify(this.certificate)
			return isValid
		} catch (err) {
			if (err instanceof Error) {
				if (err.message.toString().indexOf('The parent certificate did not issue') >= 0) {
					throw new ERROR_GENERAL_ERROR('El certificado recibido no fue emitido por el emisor, verifique que el emisor sea el correcto y que el certificado no este alterado')
				}
			}
			throw err
		}
	}

	rsaEncrypt(message: string) {
		// @ts-ignore
		const encrypted = this.certificate.publicKey['encrypt'](message)
		return encrypted
	}

	rsaVerifySignature(message: string, signature: string, algorithm: string = 'sha256', encoding?: 'utf8'): boolean {
		const messageHash = GlobalMethods.hash(message, algorithm, true, encoding)
		const messageDigest = messageHash.digest().bytes()
		// @ts-ignore
		const verified = this.certificate.publicKey['verify'](messageDigest, signature)
		return verified
	}
	getPEM() {
		return pki.certificateToPem(this.certificate)
	}
}
