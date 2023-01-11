import { asn1, pki, md } from 'node-forge'

export default class x509Certificate {
	ans1Object: asn1.Asn1
	certificate: pki.Certificate
	certificateType: string
	serialNumber: string
	acVersion: number
	valid: boolean
	constructor(x509Binary: string) {
		this.ans1Object = this.readANS1(x509Binary)
		const certificate = this.certificateFromAns1(this.ans1Object)
		this.serialNumber = certificate.serialNumber
		this.acVersion = Number(this.serialNumber[23])
		this.certificate = certificate
		this.certificateType = this.getCertiticateType()
		const now = new Date()
		if (now < certificate.validity.notAfter && now > certificate.validity.notBefore) {
			this.valid = true
		} else {
			this.valid = false
		}

	}

	private hash(input: string, algorithm: string = 'sha256', returnForgeHashObject: boolean = false) {
		// @ts-ignore
		var mdObj = md[algorithm].create()
		mdObj.update(input)
		if (returnForgeHashObject) {
			return mdObj
		}
		return mdObj.digest().toHex()
	}

	private readANS1(file: string) {
		try {
			const ans1Object = asn1.fromDer(file)
			return ans1Object
		} catch (err) {
			throw 'Verifique el archivo, no fue posible decodificar el ANS1'
		}
	}

	private certificateFromAns1(ans1Object: asn1.Asn1) {
		try {
			const certificate = pki.certificateFromAsn1(ans1Object)
			return certificate
		} catch (err) {
			throw 'Verifique el archivo, no fue posible convertir el ANS1 a certificado'
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

	verifyIntegrity(x509IssuerBinary: string) {
		const issuerCertificate = this.readANS1(x509IssuerBinary)
		const certificate = this.certificateFromAns1(issuerCertificate)
		try {
			const isValid = certificate.verify(this.certificate)
			return isValid
		} catch (err) {
			if (err.message.toString().indexOf('The parent certificate did not issue') >= 0) {
				throw 'El certificado del issuer recibido no es el de este certificado'
			}
			throw err
		}
	}

	rsaEncrypt(message: string) {
		// @ts-ignore
		const encrypted = this.certificate.publicKey['encrypt'](message)
		return encrypted
	}

	rsaVerifySignature(message: string, signature: string, algorithm: string = 'sha256'): boolean {
		const messageHash = this.hash(message, algorithm, true)
		const messageDigest = messageHash.digest().bytes()
		// @ts-ignore
		const verified = this.certificate.publicKey['verify'](messageDigest, signature)
		return verified
	}
}
