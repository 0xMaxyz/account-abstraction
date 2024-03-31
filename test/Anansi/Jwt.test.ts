import { ethers } from "hardhat";
import {
  Base64,
  Base64__factory,
  JwtValidator,
  JwtValidator__factory,
  RsaVerifyOptimized,
  RsaVerifyOptimized__factory,
} from "../../typechain";
import { preDecode } from "./base46util";
import { expect } from "chai";

describe("JWT Tests", () => {
  const jwt =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFkZjVlNzEwZWRmZWJlY2JlZmE5YTYxNDk1NjU0ZDAzYzBiOGVkZjgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyMjIwMzc4MzcxNTQtcG5oNXJkcjhkOWh2Zmo5aW9vcmU2YW1iMGdxczRiajkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyMjIwMzc4MzcxNTQtcG5oNXJkcjhkOWh2Zmo5aW9vcmU2YW1iMGdxczRiajkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDE5ODkxODYwMDE4MjUxMDI1NTAiLCJlbWFpbCI6IjB4bWF4eXpAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoieGlvbmJsYWhibGFoYmxhaGJsYWhibGFoYmxhaCIsIm5iZiI6MTcxMTQ2MDUwMiwibmFtZSI6Ik1heCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NKUDhEVWZueEptWjQ1SUN3YkJHaHhWUHIxMWZ1YUZ2czJFVE1FaHp2Y1BSdz1zOTYtYyIsImdpdmVuX25hbWUiOiJNYXgiLCJpYXQiOjE3MTE0NjA4MDIsImV4cCI6MTcxMTQ2NDQwMiwianRpIjoiNWNhYWU5MGY3NzY1ZDNkNGE2ZGNjOTBmYWVjZmRkMWZlYjY2OTk4ZCJ9.s9BYIZaIIlHzDL7cYvWNn6jyeKQa0PIgi3O8-CvEwrCr2AK7Y62Gv87tN_Ic32Dk7wL-KWI10Xg5RkBW03F8i400ZYTIdhWk2cNHxbDDLK_5AwaOI3lVEjtN_hUz14ESTpRTIBoAXRl7fsXrMXM3kfxpj7R7ILoO8RYMWiaOiCN2zjnHINRdNQFuSZrDcgtRuel2IZlMaCYZN_Tw8KEr5JsyiAephAq5EOChnrBkMaVHRLTwrSJVn_bayPmMnE7ZhcbCI99J6RqAs9u2YTOMp3d2OVCGPeCbuTq2nbmVtYSeXm-mqwdEyo2i8avdlEwKzJVKp87_syLf_PrxTDZOFA";

  const kid = "adf5e710edfebecbefa9a61495654d03c0b8edf8";
  const sub =
    "222037837154-pnh5rdr8d9hvfj9ioore6amb0gqs4bj9.apps.googleusercontent.com";
  const jwt_parts = preDecode(jwt);

  let base64Contract: Base64;
  let jwtValidatorContract: JwtValidator;
  let rsaVerifierContract: RsaVerifyOptimized;
  before("Initialize", async function () {
    const ethersSigner = ethers.provider.getSigner();
    base64Contract = await new Base64__factory(ethersSigner).deploy();
    jwtValidatorContract = await new JwtValidator__factory(
      ethersSigner
    ).deploy();
    rsaVerifierContract = await new RsaVerifyOptimized__factory(
      ethersSigner
    ).deploy();
  });
  it("Decodes base 64", async () => {
    const decoded = await base64Contract.decode(jwt_parts[0]);
    expect(
      `{"alg":"RS256","kid":"adf5e710edfebecbefa9a61495654d03c0b8edf8","typ":"JWT"}`
    ).to.equal(ethers.utils.toUtf8String(decoded));
  });
  it("Deserializes json", async () => {
    const payload = await base64Contract.decode(jwt_parts[1]);
    const toJson = ethers.utils.toUtf8String(payload);

    const output = await jwtValidatorContract.getToken(toJson);
    expect(output.aud).to.equal(sub);

    const header = await base64Contract.decode(jwt_parts[0]);
    const headerJson = ethers.utils.toUtf8String(header);

    const fromJson = await jwtValidatorContract.getToken(headerJson);
    expect(fromJson.kid).to.equal(kid);
  });

  it("Verifies signature", async () => {
    const signature = await base64Contract.decode(jwt_parts[2]);
    const base64_modulus = preDecode(
      "y48N6JB-AKq1-Rv4SkwBADU-hp4zXHU-NcCUwxD-aS9vr4EoT9qrjoJ-YmkaEpq9Bmu1yXZZK_h_9QS3xEsO8Rc_WSvIQCJtIaDQz8hxk4lUjUQjMB4Zf9vdTmf8KdktI9tCYCbuSbLC6TegjDM9kbl9CNs3m9wSVeO_5JXJQC0Jr-Oj7Gz9stXm0Co3f7RCxrD08kLelXaAglrd5TeGjZMyViC4cw1gPaj0Cj6knDn8UlzR_WuBpzs_ies5BrbzX-yht0WfnhXpdpiGNMbpKQD04MmPdMCYq8ENF7q5_Ok7dPsVj1vHA6vFGnf7qE3smD157szsnzn0NeXIbRMnuQ"
    )[0];
    const modulus = await base64Contract.decode(base64_modulus);
    const exponent = ethers.utils.hexZeroPad(ethers.utils.hexValue(65537), 256);
    const dig =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFkZjVlNzEwZWRmZWJlY2JlZmE5YTYxNDk1NjU0ZDAzYzBiOGVkZjgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyMjIwMzc4MzcxNTQtcG5oNXJkcjhkOWh2Zmo5aW9vcmU2YW1iMGdxczRiajkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyMjIwMzc4MzcxNTQtcG5oNXJkcjhkOWh2Zmo5aW9vcmU2YW1iMGdxczRiajkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDE5ODkxODYwMDE4MjUxMDI1NTAiLCJlbWFpbCI6IjB4bWF4eXpAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoieGlvbmJsYWhibGFoYmxhaGJsYWhibGFoYmxhaCIsIm5iZiI6MTcxMTQ2MDUwMiwibmFtZSI6Ik1heCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NKUDhEVWZueEptWjQ1SUN3YkJHaHhWUHIxMWZ1YUZ2czJFVE1FaHp2Y1BSdz1zOTYtYyIsImdpdmVuX25hbWUiOiJNYXgiLCJpYXQiOjE3MTE0NjA4MDIsImV4cCI6MTcxMTQ2NDQwMiwianRpIjoiNWNhYWU5MGY3NzY1ZDNkNGE2ZGNjOTBmYWVjZmRkMWZlYjY2OTk4ZCJ9";
    const isValid = await rsaVerifierContract.pkcs1Sha256(
      ethers.utils.sha256(ethers.utils.toUtf8Bytes(dig)),
      signature,
      exponent,
      modulus
    );
    expect(isValid).to.be.true;
    // devoce modules
    const m1 =
      "vdtZ3cfuh44JlWkJRu-3yddVp58zxSHwsWiW_jpaXgpebo0an7qY2IEs3D7kC186Bwi0T7Km9mUcDbxod89IbtZuQQuhxlgaXB-qX9GokNLdqg69rUaealXGrCdKOQ-rOBlNNGn3M4KywEC98KyQAKXe7prs7yGqI_434rrULaE7ZFmLAzsYNoZ_8l53SGDiRaUrZkhxXOEhlv1nolgYGIH2lkhEZ5BlU53BfzwjO-bLeMwxJIZxSIOy8EBIMLP7eVu6AIkAr9MaDPJqeF7n7Cn8yv_qmy51bV-INRS-HKRVriSoUxhQQTbvDYYvJzHGYu_ciJ4oRYKkDEwxXztUew";
    const m2 =
      "y48N6JB-AKq1-Rv4SkwBADU-hp4zXHU-NcCUwxD-aS9vr4EoT9qrjoJ-YmkaEpq9Bmu1yXZZK_h_9QS3xEsO8Rc_WSvIQCJtIaDQz8hxk4lUjUQjMB4Zf9vdTmf8KdktI9tCYCbuSbLC6TegjDM9kbl9CNs3m9wSVeO_5JXJQC0Jr-Oj7Gz9stXm0Co3f7RCxrD08kLelXaAglrd5TeGjZMyViC4cw1gPaj0Cj6knDn8UlzR_WuBpzs_ies5BrbzX-yht0WfnhXpdpiGNMbpKQD04MmPdMCYq8ENF7q5_Ok7dPsVj1vHA6vFGnf7qE3smD157szsnzn0NeXIbRMnuQ";

    const dm1 = Buffer.from(m1, "base64").toString("hex");
    const dm2 = Buffer.from(m2, "base64").toString("hex");
  });

  it("verifies mock signature with 2048 bytes key", async function () {
    const message = ethers.utils.sha256(
      ethers.utils.toUtf8Bytes("hello world")
    );
    const modulus =
      "0xC93E1BD98562158C2DFCB14F2151C49CFCFEFD5C69F3B19470ED23BCA39B069EAAF28DD346A9BB43C37F867FF64E93D0843FBF61B54EEBC7F02984FD7216B047F5FF10DE088DF08934C1273001AD5C5E6D078161036D80484E25461C8067F9C8CF63B8539F2D4B1A8B7125BB02D5DC8933D3F361B008F2C71EA62F56CA83085FFC2CAF37A49004D6A933DB67B1F6F7D70AECE6C4788305D45D8C04BFFDD1DE4C534583DE1D4419F9D8BD92BA1DF397AE6C942D922C6732CAABC5C8556F3271F6A07FD63AE9AE83756D18DED8DC161535AFEDE0CD7A88E8C68A6A0A09E36E6432A97B04E1CCC5B34AFC18946790E18A4371CE0690A6D4AEE5A1D27C131E67D577";
    const exponent =
      "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
    const signature =
      "0x78321c8c54df34965435f2c4cbd087097abb925d0615793aeb86c82a66ead651c0f7eef0ed52a4a36aa14ba1165c394368d74870480b12f8746f9b67a887ecc254f9741ccd579366ae8a531fc88095c42aaf2d678551c75c82700167304cc67870b429239d2af6bcc5b881b89a18d585218edad3baf2b53d712c10f1eadf4249af0909efdd7b7b927e139397838e22a8efd180831c5fdbbcf3bf10383de5877df5227976892a2aaf655361f9825483902a11afc9e962d67344268cd6e0997f6e9b04cab7644de104df6428a614f75f73278e193bc2721e4f1a21b26bbaeeb624d2634246ca6f9dd04fddb34c4f492803cbe122df47b4b54a133215eddd6b5ce6";

    const result = await rsaVerifierContract.pkcs1Sha256(
      message,
      signature,
      exponent,
      modulus
    );
    expect(result).to.be.true;
  });
});
