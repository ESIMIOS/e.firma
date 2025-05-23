import { asn1, md, util } from "node-forge";
import ERROR_GENERAL_ERROR from "./errors/ERROR_GENERAL_ERROR";

export class GlobalMethods {
  constructor() {}
  static hash(
    input: string,
    algorithm: string = "sha256",
    returnForgeHashObject: boolean = false,
    encoding?: "utf8" | "",
  ): any {
    //@ts-ignore
    const mdObj = md[algorithm].create();
    if (encoding) {
      mdObj.update(input, encoding);
    } else {
      mdObj.update(input);
    }

    if (returnForgeHashObject) {
      return mdObj;
    }
    return mdObj.digest().toHex();
  }
  static readASN1(file: string) {
    try {
      const asn1Object = asn1.fromDer(file);
      return asn1Object;
    } catch (err) {
      throw new ERROR_GENERAL_ERROR(
        "Verifique el archivo, no fue posible decodificar el ASN1",
      );
    }
  }
  static binaryToBase64(binary: string) {
    return util.encode64(binary);
  }
  static base64ToBinary(base64String: string) {
    return util.decode64(base64String);
  }
}
