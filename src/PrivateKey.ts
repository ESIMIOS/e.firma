import { asn1, pki, md } from 'node-forge'
export default class x509Certificate {
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
		this.ans1Object = this.readANS1(x509Binary)
		let errors: Array<string> = []
		// @ts-ignore
		const isEncrypted = asn1['validate'](this.ans1Object, this.encryptedPrivateKeyValidator, null, errors)
		if (!isEncrypted) {
			const message = `Llave privada no válida \n${errors.join('\n')}`
			throw message
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

	rsaDecrypt(encryptedText: string, passwordKey: string) {
		const privateKeyInfo = pki.decryptPrivateKeyInfo(this.ans1Object, passwordKey)
		const pem = pki.privateKeyInfoToPem(privateKeyInfo)
		const privateKey = pki.privateKeyFromPem(pem)
		const plainText = privateKey.decrypt(encryptedText)
		return plainText
	}

	rsaSign(message: string, passwordKey: string) {
		const privateKeyInfo = pki.decryptPrivateKeyInfo(this.ans1Object, passwordKey)
		const pem = pki.privateKeyInfoToPem(privateKeyInfo)
		const privateKey = pki.privateKeyFromPem(pem)
		const messageHash = this.hash(message, 'sha256', true)
		const signature = privateKey.sign(messageHash)
		return signature
	}
}
