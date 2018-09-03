### pdf
#### [PDFiD]
 - **PDF Header:** `%PDF-1.1`
 - **Total Entropy:** `7.873045`
 - **Entropy In Streams:** `7.970107`
 - **Entropy Out Streams:** `4.896895`
 - **Count %% EOF:** `1`
 - **Data After EOF:** `0`

| Keyword     | Count     |
|-------------|-----------|
| obj      | 9        |
| endobj      | 9        |
| stream      | 2        |
| endstream      | 2        |
| xref      | 1        |
| trailer      | 1        |
| startxref      | 1        |
| /Page      | 1        |
| /Encrypt      | 0        |
| /ObjStm      | 0        |
| /JS      | 1        |
| /JavaScript      | 1        |
| /AA      | 0        |
| /OpenAction      | 1        |
| /AcroForm      | 0        |
| /JBIG2Decode      | 0        |
| /RichMedia      | 0        |
| /Launch      | 0        |
| /EmbeddedFile      | 1        |
| /XFA      | 0        |
| /Colors > 2^24      | 0        |

##### Embedded File
> **Score:** `50`

**Reasons:**
 - `/EmbeddedFile` flag(s) detected

##### Triage
> **Score:** `150`

**Reasons:**
- `/JS`: indicating javascript is present in the file.
- `/JavaScript`: indicating javascript is present in the file.
- `/OpenAction`: indicating automatic action to be performed when the page/document is viewed.

##### Suspicious Properties
> **Score:** `50`

**Reasons:**
- Page count of 1

#### [pdf-parser]



##### TAGS
**file_name:**
- `eicar-dropper.doc`

**pestudio_blacklist_string:**
- `JavaScript`


##### Embedded Files
| Object      | Sha256   |
|-------------|----------|
| 8 | eb0ae2d1cd318dc1adb970352e84361f9b194ff14f45b0186e4ed6696900394a |



##### Carved Content
**EmbeddedFile:**
```
s<<++<<            /Names [(eicar-dropper.doc) 7 0 R]    /OpenAction 9 0 R
```
**OpenAction:**
```

<<
 /Type /Action
 /S /JavaScript
 /JS (this.exportDataObject({ cName: "eicar-dropper.doc", nLaunch: 2 });)
>>

```
**JS:**
```javascript
(this.exportDataObject({ cName: "eicar-dropper.doc", nLaunch: 2 })    ; )
```

