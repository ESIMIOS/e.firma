import { asn1, md } from 'node-forge'
import ERROR_GENERAL_ERROR from './errors/ERROR_GENERAL_ERROR'
export class GlobalMethods {
	constructor() {}
	static hash(input: string, algorithm: string = 'sha256', returnForgeHashObject: boolean = false): any {
		//@ts-ignore
		var mdObj = md[algorithm].create()
		mdObj.update(input)
		if (returnForgeHashObject) {
			return mdObj
		}
		return mdObj.digest().toHex()
	}
	static readASN1(file: string) {
		try {
			const ans1Object = asn1.fromDer(file)
			return ans1Object
		} catch (err) {
			throw new ERROR_GENERAL_ERROR('Verifique el archivo, no fue posible decodificar el ANS1')
		}
	}
}
