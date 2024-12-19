# CVE CHECKER

![un license](https://img.shields.io/github/license/RyosukeDTomita/cve_checker)

## INDEX

- [ABOUT](#about)
- [ENVIRONMENT](#environment)
- [PREPARING](#preparing)

---

## ABOUT

AWS Lambda to hit [NVD API](https://nvd.nist.gov/developers/vulnerabilities) to get CVE information

---

## ENVIRONMENT

- AWS Lambda
- Python3.12

---

## PREPARING

1. set up `serverless`. See [Getting Started](https://www.serverless.com/framework/docs/getting-started)
2. clone this repository
3. `serverless deploy`

```shell
cd cvechecker
sls deploy
```

