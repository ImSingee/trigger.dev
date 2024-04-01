import type { BinaryToTextEncoding, BinaryLike, KeyObject } from "crypto";
import { VerifyResult } from "./types";

/** Easily verify webhook payloads when they're using common signing methods. */
export async function verifyRequestSignature({
  request,
  headerName,
  headerEncoding = "hex",
  secret,
  algorithm,
}: {
  /** The web request that you want to verify. */
  request: Request;
  /** The name of the header that contains the signature. E.g. `X-Cal-Signature-256`. */
  headerName: string;
  /** The header encoding. Defaults to `hex`. */
  headerEncoding?: BinaryToTextEncoding;
  /** The secret that you use to hash the payload. For HttpEndpoints this will usually originally
      come from the Trigger.dev dashboard and should be stored in an environment variable. */
  secret: BinaryLike | KeyObject;
  /** The hashing algorithm that was used to create the signature. Currently only `sha256` is
      supported. */
  algorithm: "sha256";
}): Promise<VerifyResult> {
  if (!secret) {
    return {
      success: false,
      reason: "Missing secret – you've probably not set an environment variable.",
    };
  }

  const headerValue = request.headers.get(headerName);
  if (!headerValue) {
    return { success: false, reason: "Missing header" };
  }

  switch (algorithm) {
    case "sha256":
      const success = await verifyHmacSha256(headerValue, headerEncoding, secret, await request.text());

      if (success) {
        return {
          success,
        };
      } else {
        return { success: false, reason: "Failed sha256 verification" };
      }
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

export async function verifyHmacSha256(
  headerValue: string,
  headerEncoding: BinaryToTextEncoding,
  secret: BinaryLike | KeyObject,
  body: string
): Promise<boolean> {
  const bodyDigest = await createHmac(secret, body, headerEncoding);
  const signature = headerValue?.replace("hmac-sha256=", "").replace("sha256=", "") ?? "";

  return signature === bodyDigest;
}

async function createHmac(secret: BinaryLike | KeyObject, data: string, headerEncoding: BinaryToTextEncoding) {
  if (typeof secret !== 'string') {
    throw new Error('secret must be a string now');
  }

  let key = await crypto.subtle.importKey(
    'raw',
    Buffer.from(secret),
    { name: 'HMAC', hash: 'SHA-256' }, // 这里假定使用SHA-256，你可以根据需要更改
    false,
    ['sign']
  );

  // 对数据进行HMAC操作
  let signature = await crypto.subtle.sign(
    'HMAC',
    key,
    Buffer.from(data)
  );

  return Buffer.from(signature).toString(headerEncoding);
}