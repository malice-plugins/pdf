# Create a PDF scan micro-service

```bash
$ docker run -d -p 3993:3993 malice/pdf web

INFO[0000] web service listening on port :3993
```

## Now you can perform scans like so

```bash
$ http -f localhost:3993/scan malware@/path/to/evil/malware
```

> **NOTE:** I am using **httpie** to POST to the malice micro-service

```bash
HTTP/1.1 200 OK
Content-Length: 124
Content-Type: application/json; charset=UTF-8
Date: Sat, 21 Jan 2017 05:39:29 GMT

{
  "pdf": {
    "streams": {},
    "peepdf": {},
    "markdown":
      "\n#### PDF\n#### PDFiD\n - **PDF Header:** `%PDF-1.1`\n - **Total Entropy:** `7.873045`\n - **Entropy In Streams:** `7.970107`\n - **EntropyOut Streams:** `4.896895`\n - **Count %% EOF:** `1`\n - **Data After EOF:** `0`\n\n**Embedded File:**\n - **Score:** `0.9`\n - **Reason:** `/EmbeddedFile` flag(s) detected\n\n**Triage:**\n - **Score:** `1.0`\n - **Reason:** sample is likely malicious and requires further analysis\n\n| Keyword     | Count     |\n|-------------|-----------|\n| obj      | 9        |\n| endobj      | 9        |\n| stream      | 2        |\n| endstream      | 2        |\n| xref      | 1        |\n| trailer      | 1        |\n| startxref      | 1        |\n| /Page      | 1        |\n| /Encrypt      | 0        |\n| /ObjStm      | 0        |\n| /JS      | 1|\n| /JavaScript      | 1        |\n| /AA      | 0        |\n| /OpenAction      | 1        |\n| /AcroForm      | 0        |\n| /JBIG2Decode      | 0        |\n| /RichMedia      | 0        |\n| /Launch      | 0        |\n| /EmbeddedFile      | 1        |\n| /XFA      | 0        |\n| /Colors > 2^24      | 0        |\n",
    "pdfid": {
      "heuristics": {
        "embeddedfile": {
          "reason": "`/EmbeddedFile` flag(s) detected",
          "score": 0.9
        },
        "nameobfuscation": {
          "reason": "no hex encoded flags detected",
          "score": 0
        },
        "suspicious": {},
        "triage": {
          "reason": "sample is likely malicious and requires further analysis",
          "score": 1
        }
      },
      "countChatAfterLastEof": "0",
      "errorMessage": "",
      "dates": {
        "date": []
      },
      "nonStreamEntropy": "4.896895",
      "header": "%PDF-1.1",
      "version": "0.2.4",
      "entropy": "",
      "totalEntropy": "7.873045",
      "isPdf": "True",
      "keywords": {
        "keyword": [
          {
            "count": 9,
            "hexcodecount": 0,
            "name": "obj"
          },
          {
            "count": 9,
            "hexcodecount": 0,
            "name": "endobj"
          },
          {
            "count": 2,
            "hexcodecount": 0,
            "name": "stream"
          },
          {
            "count": 2,
            "hexcodecount": 0,
            "name": "endstream"
          },
          {
            "count": 1,
            "hexcodecount": 0,
            "name": "xref"
          },
          {
            "count": 1,
            "hexcodecount": 0,
            "name": "trailer"
          },
          {
            "count": 1,
            "hexcodecount": 0,
            "name": "startxref"
          },
          {
            "count": 1,
            "hexcodecount": 0,
            "name": "/Page"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/Encrypt"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/ObjStm"
          },
          {
            "count": 1,
            "hexcodecount": 0,
            "name": "/JS"
          },
          {
            "count": 1,
            "hexcodecount": 0,
            "name": "/JavaScript"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/AA"
          },
          {
            "count": 1,
            "hexcodecount": 0,
            "name": "/OpenAction"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/AcroForm"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/JBIG2Decode"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/RichMedia"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/Launch"
          },
          {
            "count": 1,
            "hexcodecount": 0,
            "name": "/EmbeddedFile"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/XFA"
          },
          {
            "count": 0,
            "hexcodecount": 0,
            "name": "/Colors > 2^24"
          }
        ]
      },
      "countEof": "1",
      "streamEntropy": "7.970107",
      "errorOccured": "False"
    }
  }
}
```
