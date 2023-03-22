import { asn1, pki, util } from 'node-forge'
import { GlobalMethods } from './GlobalMethods'
import ERROR_GENERAL_ERROR from './errors/ERROR_GENERAL_ERROR'
export class PrivateKey {
	private ans1Object: asn1.Asn1
	private encryptedPrivateKeyValidator = {
		tagClass: asn1.Class.UNIVERSAL,
		type: asn1.Type.SEQUENCE,
		constructed: true,
		value: [
			{
				tagClass: asn1.Class.UNIVERSAL,
				type: asn1.Type.SEQUENCE,
				constructed: true,
				value: [
					{
						tagClass: asn1.Class.UNIVERSAL,
						type: asn1.Type.OID,
						constructed: false
					},
					{
						tagClass: asn1.Class.UNIVERSAL,
						type: asn1.Type.SEQUENCE,
						constructed: true,
						value: [
							{
								tagClass: asn1.Class.UNIVERSAL,
								type: asn1.Type.SEQUENCE,
								constructed: true,
								value: [
									{
										tagClass: asn1.Class.UNIVERSAL,
										type: asn1.Type.OID,
										constructed: false
									},
									{
										tagClass: asn1.Class.UNIVERSAL,
										type: asn1.Type.SEQUENCE,
										constructed: true,
										value: [
											{
												tagClass: asn1.Class.UNIVERSAL,
												type: asn1.Type.OCTETSTRING,
												constructed: false
											},
											{
												tagClass: asn1.Class.UNIVERSAL,
												type: asn1.Type.INTEGER,
												constructed: false
											}
										]
									}
								]
							},
							{
								tagClass: asn1.Class.UNIVERSAL,
								type: asn1.Type.SEQUENCE,
								constructed: true,
								value: [
									{
										tagClass: asn1.Class.UNIVERSAL,
										type: asn1.Type.OID,
										constructed: false
									},
									{
										tagClass: asn1.Class.UNIVERSAL,
										type: asn1.Type.OCTETSTRING,
										constructed: false
									}
								]
							}
						]
					}
				]
			},
			{
				// encryptedData
				tagClass: asn1.Class.UNIVERSAL,
				type: asn1.Type.OCTETSTRING,
				constructed: false
			}
		]
	}

	constructor(x509Binary: string) {
		this.ans1Object = GlobalMethods.readASN1(x509Binary)
		let errors: Array<string> = []
		// @ts-ignore
		const isEncrypted = asn1['validate'](this.ans1Object, this.encryptedPrivateKeyValidator, null, errors)
		if (!isEncrypted) {
			const message = `Llave privada no válida \n${errors.join('\n')}`
			throw new ERROR_GENERAL_ERROR(message)
		}
	}

	rsaDecrypt(encryptedText: string, passwordKey: string) {
		const privateKeyInfo = pki.decryptPrivateKeyInfo(this.ans1Object, passwordKey)
		const pem = pki.privateKeyInfoToPem(privateKeyInfo)
		const privateKey = pki.privateKeyFromPem(pem)
		const plainText = privateKey.decrypt(encryptedText)
		return plainText
	}

	rsaSign(message: string, passwordKey: string, encoding?: 'utf8') {
		const privateKeyInfo = pki.decryptPrivateKeyInfo(this.ans1Object, passwordKey)
		const pem = pki.privateKeyInfoToPem(privateKeyInfo)
		const privateKey = pki.privateKeyFromPem(pem)
		const messageHash = GlobalMethods.hash(message, 'sha256', true, encoding)
		const signature = privateKey.sign(messageHash)
		return signature
	}
}
