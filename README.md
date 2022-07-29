# `aws-cognito-srp-client`

> SRP Client for AWS Cognito UserPools SRP Auth Flow

This file can be bundled to work in browser, also works in nodejs.

## Usage

Use this library in conjunction with InitiateAuth Api of Cognito

- **Step 1**  
  Generate SRP_A

  ```TS
  import Srp from "aws-cognito-srp-client";

  const srp = new Srp(userPoolId);

  const srpA = srp.getA();
  ```

- **Step 2**
  Invoke [initiateAuth](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CognitoIdentityServiceProvider.html#initiateAuth-property) Api with `USER_SRP_AUTH` AuthFlow  
  Use SPP_A generated from step 1 to pass input to `initialteAuth` API

- **Step 3**
  Calculate `signature` and `timestamp`

  ```TS
  import Srp from "aws-cognito-srp-client";

  const { signature, timestamp } = srp.getSignature(
    userId,
    srpB,
    salt,
    secret,
    password
  );

  ```

  **userId**, **srpB**, **salt**, and **secret** are available in the response of `initialteAuth` API

- **Step 4**
  Invoke [respondToAuthChallenge](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CognitoIdentityServiceProvider.html#respondToAuthChallenge-property) Api with `PASSWORD_VERIFIER` ChallengeName
  Use `signature` and `timestamp` from step 3 to passinput to `respondToAuthChallenge` API.

## Support

This project is a part of Open Source Intitiative from [Sodaru Technologies](https://sodaru.com)

Write an email to opensource@sodaru.com for queries on this project
