"""
Modified by CSE to fit ASSEMBLYLINE service
"""

__description__ = 'pdf-parser, use it to parse a PDF document'
__author__ = 'Didier Stevens'
__version__ = '0.6.8'
__date__ = '2017/10/29'
__minimum_python_version__ = (2, 5, 1)
__maximum_python_version__ = (3, 6, 3)
"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/05/02: continue
  2008/05/03: continue
  2008/06/02: streams
  2008/10/19: refactor, grep & extract functionality
  2008/10/20: reference
  2008/10/21: cleanup
  2008/11/12: V0.3 dictionary parser
  2008/11/13: option elements
  2008/11/14: continue
  2009/05/05: added /ASCIIHexDecode support (thanks Justin Prosco)
  2009/05/11: V0.3.1 updated usage, added --verbose and --extract
  2009/07/16: V0.3.2 Added Canonicalize (thanks Justin Prosco)
  2009/07/18: bugfix EqualCanonical
  2009/07/24: V0.3.3 Added --hash option
  2009/07/25: EqualCanonical for option --type, added option --nocanonicalizedoutput
  2009/07/28: V0.3.4 Added ASCII85Decode support
  2009/08/01: V0.3.5 Updated ASCIIHexDecode to support whitespace obfuscation
  2009/08/30: V0.3.6 TestPythonVersion
  2010/01/08: V0.3.7 Added RLE and LZW support (thanks pARODY); added dump option
  2010/01/09: Fixed parsing of incomplete startxref
  2010/09/22: V0.3.8 Changed dump option, updated PrettyPrint, added debug option
  2011/12/17: fixed bugs empty objects
  2012/03/11: V0.3.9 fixed bugs double nested [] in PrettyPrintSub (thanks kurt)
  2013/01/11: V0.3.10 Extract and dump bug fixes by Priit; added content option
  2013/02/16: Performance improvement in cPDFTokenizer by using StringIO for token building by Christophe Vandeplas; xrange replaced with range
  2013/02/16: V0.4.0 added http/https support; added error handling for missing file or URL; ; added support for ZIP file with password 'infected'
  2013/03/13: V0.4.1 fixes for Python 3
  2013/04/11: V0.4.2 modified PrettyPrintSub for strings with unprintable characters
  2013/05/04: Added options searchstream, unfiltered, casesensitive, regex
  2013/09/18: V0.4.3 fixed regression bug -w option
  2014/09/25: V0.5.0 added option -g
  2014/09/29: Added PrintGenerateObject and PrintOutputObject
  2014/12/05: V0.6.0 Added YARA support
  2014/12/09: cleanup, refactoring
  2014/12/13: Python 3 fixes
  2015/01/11: Added support for multiple YARA rule files; added request to search in trailer
  2015/01/31: V0.6.1 Added optionyarastrings
  2015/02/09: Added decoders
  2015/04/05: V0.6.2 Added generateembedded
  2015/04/06: fixed bug reported by Kurt for stream produced by Ghostscript where endstream is not preceded by whitespace; fixed prettyprint bug
  2015/04/24: V0.6.3 when option dump's filename is -, content is dumped to stdout
  2015/08/12: V0.6.4 option hash now also calculates hashes of streams when selecting or searching objects; and displays hexasciidump first line
  2016/07/27: V0.6.5 bugfix whitespace 0x00 0x0C after stream 0x0D 0x0A reported by @mr_me
  2016/11/20: V0.6.6 added workaround zlib errors FlateDecode
  2016/12/17: V0.6.7 added option -k
  2017/01/07: V0.6.8 changed cPDFParseDictionary to handle strings () with % character
  2017/10/28: fixed bug
  2017/10/29: added # support for option -y

Todo:
  - handle printf todo
  - support for JS hex string EC61C64349DB8D88AF0523C4C06E0F4D.pdf.vir

"""

import re
import optparse
import zlib
import binascii
import hashlib
import sys
import zipfile
import time
import os
if sys.version_info[0] >= 3:
    from io import StringIO
    import urllib.request
    urllib23 = urllib.request
else:
    from cStringIO import StringIO
    import urllib2
    urllib23 = urllib2
try:
    import yara
except:
    pass

CHAR_WHITESPACE = 1
CHAR_DELIMITER = 2
CHAR_REGULAR = 3

CONTEXT_NONE = 1
CONTEXT_OBJ = 2
CONTEXT_XREF = 3
CONTEXT_TRAILER = 4

PDF_ELEMENT_COMMENT = 1
PDF_ELEMENT_INDIRECT_OBJECT = 2
PDF_ELEMENT_XREF = 3
PDF_ELEMENT_TRAILER = 4
PDF_ELEMENT_STARTXREF = 5
PDF_ELEMENT_MALFORMED = 6

dumplinelength = 16


#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string


# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression


# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)


def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]


def CopyWithoutWhiteSpace(content):
    result = []
    for token in content:
        if token[0] != CHAR_WHITESPACE:
            result.append(token)
    return result


def Obj2Str(content):
    return ''.join(map(lambda x: repr(x[1])[1:-1], CopyWithoutWhiteSpace(content)))


class cPDFDocument:

    def __init__(self, filepath):
        self.file = filepath
        if type(filepath) != str:
            self.infile = filepath
        elif filepath.lower().startswith('http://') or filepath.lower().startswith('https://'):
            try:
                if sys.hexversion >= 0x020601F0:
                    self.infile = urllib23.urlopen(filepath, timeout=5)
                else:
                    self.infile = urllib23.urlopen(filepath)
            except urllib23.HTTPError:
                print('Error accessing URL %s' % filepath)
                print(sys.exc_info()[1])
                sys.exit()
        elif filepath.lower().endswith('.zip'):
            try:
                self.zipfile = zipfile.ZipFile(filepath, 'r')
                self.infile = self.zipfile.open(self.zipfile.infolist()[0], 'r', C2BIP3('infected'))
            except:
                print('Error opening file %s' % filepath)
                print(sys.exc_info()[1])
                sys.exit()
        else:
            try:
                self.infile = open(filepath, 'rb')
            except:
                raise Exception('Error opening file %s' % filepath)
        self.ungetted = []
        self.position = -1

    def byte(self):
        if len(self.ungetted) != 0:
            self.position += 1
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte or inbyte == '':
            self.infile.close()
            return None
        self.position += 1
        return ord(inbyte)

    def unget(self, byte):
        self.position -= 1
        self.ungetted.append(byte)


def CharacterClass(byte):
    if byte == 0 or byte == 9 or byte == 10 or byte == 12 or byte == 13 or byte == 32:
        return CHAR_WHITESPACE
    if byte == 0x28 or byte == 0x29 or byte == 0x3C or byte == 0x3E or byte == 0x5B or byte == 0x5D or byte == 0x7B or byte == 0x7D or byte == 0x2F or byte == 0x25:
        return CHAR_DELIMITER
    return CHAR_REGULAR


def IsNumeric(str):
    return re.match('^[0-9]+', str)


class cPDFTokenizer:

    def __init__(self, file):
        try:
            self.oPDF = cPDFDocument(file)
        except Exception as e:
            raise Exception(e)
        self.ungetted = []

    def Token(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        if self.oPDF == None:
            return None
        self.byte = self.oPDF.byte()
        if self.byte == None:
            self.oPDF = None
            return None
        elif CharacterClass(self.byte) == CHAR_WHITESPACE:
            file_str = StringIO()
            while self.byte != None and CharacterClass(self.byte) == CHAR_WHITESPACE:
                file_str.write(chr(self.byte))
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            else:
                self.oPDF = None
            self.token = file_str.getvalue()
            return (CHAR_WHITESPACE, self.token)
        elif CharacterClass(self.byte) == CHAR_REGULAR:
            file_str = StringIO()
            while self.byte != None and CharacterClass(self.byte) == CHAR_REGULAR:
                file_str.write(chr(self.byte))
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            else:
                self.oPDF = None
            self.token = file_str.getvalue()
            return (CHAR_REGULAR, self.token)
        else:
            if self.byte == 0x3C:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3C:
                    return (CHAR_DELIMITER, '<<')
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, '<')
            elif self.byte == 0x3E:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3E:
                    return (CHAR_DELIMITER, '>>')
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, '>')
            elif self.byte == 0x25:
                file_str = StringIO()
                while self.byte != None:
                    file_str.write(chr(self.byte))
                    if self.byte == 10 or self.byte == 13:
                        self.byte = self.oPDF.byte()
                        break
                    self.byte = self.oPDF.byte()
                if self.byte != None:
                    if self.byte == 10:
                        file_str.write(chr(self.byte))
                    else:
                        self.oPDF.unget(self.byte)
                else:
                    self.oPDF = None
                self.token = file_str.getvalue()
                return (CHAR_DELIMITER, self.token)
            return (CHAR_DELIMITER, chr(self.byte))

    def TokenIgnoreWhiteSpace(self):
        token = self.Token()
        while token != None and token[0] == CHAR_WHITESPACE:
            token = self.Token()
        return token

    def Tokens(self):
        tokens = []
        token = self.Token()
        while token != None:
            tokens.append(token)
            token = self.Token()
        return tokens

    def unget(self, byte):
        self.ungetted.append(byte)


class cPDFParser:

    def __init__(self, file, verbose=False, extract=None):
        self.context = CONTEXT_NONE
        self.content = []
        try:
            self.oPDFTokenizer = cPDFTokenizer(file)
        except Exception as e:
            raise Exception(e)
        self.verbose = verbose
        self.extract = extract

    def GetObject(self):
        while True:
            if self.context == CONTEXT_OBJ:
                self.token = self.oPDFTokenizer.Token()
            else:
                self.token = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
            if self.token:
                if self.token[0] == CHAR_DELIMITER:
                    if self.token[1][0] == '%':
                        if self.context == CONTEXT_OBJ:
                            self.content.append(self.token)
                        else:
                            return cPDFElementComment(self.token[1])
                    elif self.token[1] == '/':
                        self.token2 = self.oPDFTokenizer.Token()
                        if self.token2[0] == CHAR_REGULAR:
                            if self.context != CONTEXT_NONE:
                                self.content.append((CHAR_DELIMITER, self.token[1] + self.token2[1]))
                            # elif self.verbose:
                            #     print('todo 1: %s' % (self.token[1] + self.token2[1]))
                        else:
                            self.oPDFTokenizer.unget(self.token2)
                            if self.context != CONTEXT_NONE:
                                self.content.append(self.token)
                            # elif self.verbose:
                            #     print('todo 2: %d %s' % (self.token[0], repr(self.token[1])))
                    elif self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    # elif self.verbose:
                    #     print('todo 3: %d %s' % (self.token[0], repr(self.token[1])))
                elif self.token[0] == CHAR_WHITESPACE:
                    if self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    # elif self.verbose:
                    #     print('todo 4: %d %s' % (self.token[0], repr(self.token[1])))
                else:
                    if self.context == CONTEXT_OBJ:
                        if self.token[1] == 'endobj':
                            self.oPDFElementIndirectObject = cPDFElementIndirectObject(
                                self.objectId, self.objectVersion, self.content)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementIndirectObject
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_TRAILER:
                        if self.token[1] == 'startxref' or self.token[1] == 'xref':
                            self.oPDFElementTrailer = cPDFElementTrailer(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementTrailer
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_XREF:
                        if self.token[1] == 'trailer' or self.token[1] == 'xref':
                            self.oPDFElementXref = cPDFElementXref(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementXref
                        else:
                            self.content.append(self.token)
                    else:
                        if IsNumeric(self.token[1]):
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if IsNumeric(self.token2[1]):
                                self.token3 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                                if self.token3[1] == 'obj':
                                    self.objectId = eval(self.token[1])
                                    self.objectVersion = eval(self.token2[1])
                                    self.context = CONTEXT_OBJ
                                else:
                                    self.oPDFTokenizer.unget(self.token3)
                                    self.oPDFTokenizer.unget(self.token2)
                                    # if self.verbose:
                                    #     print('todo 6: %d %s' % (self.token[0], repr(self.token[1])))
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                # if self.verbose:
                                #     print('todo 7: %d %s' % (self.token[0], repr(self.token[1])))
                        elif self.token[1] == 'trailer':
                            self.context = CONTEXT_TRAILER
                            self.content = [self.token]
                        elif self.token[1] == 'xref':
                            self.context = CONTEXT_XREF
                            self.content = [self.token]
                        elif self.token[1] == 'startxref':
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if self.token2 and IsNumeric(self.token2[1]):
                                return cPDFElementStartxref(eval(self.token2[1]))
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                # if self.verbose:
                                #     print('todo 9: %d %s' % (self.token[0], repr(self.token[1])))
                        elif self.extract:
                            self.bytes = ''
                            while self.token:
                                self.bytes += self.token[1]
                                self.token = self.oPDFTokenizer.Token()
                            return cPDFElementMalformed(self.bytes)
                        # elif self.verbose:
                        #     print('todo 10: %d %s' % (self.token[0], repr(self.token[1])))
            else:
                break


class cPDFElementComment:

    def __init__(self, comment):
        self.type = PDF_ELEMENT_COMMENT
        self.comment = comment


#                        if re.match('^%PDF-[0-9]\.[0-9]', self.token[1]):
#                            print(repr(self.token[1]))
#                        elif re.match('^%%EOF', self.token[1]):
#                            print(repr(self.token[1]))


class cPDFElementXref:

    def __init__(self, content):
        self.type = PDF_ELEMENT_XREF
        self.content = content


class cPDFElementTrailer:

    def __init__(self, content):
        self.type = PDF_ELEMENT_TRAILER
        self.content = content

    def Contains(self, keyword):
        data = ''
        for i in range(0, len(self.content)):
            if self.content[i][1] == 'stream':
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1


def IIf(expr, truepart, falsepart):
    if expr:
        return truepart
    else:
        return falsepart


class cPDFElementIndirectObject:

    def __init__(self, id, version, content):
        self.type = PDF_ELEMENT_INDIRECT_OBJECT
        self.id = id
        self.version = version
        self.content = content
        #fix stream for Ghostscript bug reported by Kurt
        if self.ContainsStream():
            position = len(self.content) - 1
            if position < 0:
                return
            while self.content[position][0] == CHAR_WHITESPACE and position >= 0:
                position -= 1
            if position < 0:
                return
            if self.content[position][0] != CHAR_REGULAR:
                return
            if self.content[position][1] == 'endstream':
                return
            if not self.content[position][1].endswith('endstream'):
                return
            self.content = self.content[0:position] + [
                (self.content[position][0], self.content[position][1][:-len('endstream')])
            ] + [(self.content[position][0], 'endstream')] + self.content[position + 1:]

    def GetType(self):
        content = CopyWithoutWhiteSpace(self.content)
        dictionary = 0
        for i in range(0, len(content)):
            if content[i][0] == CHAR_DELIMITER and content[i][1] == '<<':
                dictionary += 1
            if content[i][0] == CHAR_DELIMITER and content[i][1] == '>>':
                dictionary -= 1
            if dictionary == 1 and content[i][0] == CHAR_DELIMITER and EqualCanonical(content[i][1],
                                                                                      '/Type') and i < len(content) - 1:
                return content[i + 1][1]
        return ''

    def GetReferences(self):
        content = CopyWithoutWhiteSpace(self.content)
        references = []
        for i in range(0, len(content)):
            if i > 1 and content[i][0] == CHAR_REGULAR and content[i][1] == 'R' and content[i - 2][0] == CHAR_REGULAR and IsNumeric(
                    content[i - 2][1]) and content[i - 1][0] == CHAR_REGULAR and IsNumeric(content[i - 1][1]):
                references.append((content[i - 2][1], content[i - 1][1], content[i][1]))
        return references

    def References(self, index):
        for ref in self.GetReferences():
            if ref[0] == index:
                return True
        return False

    def ContainsStream(self):
        for i in range(0, len(self.content)):
            if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                return self.content[0:i]
        return False

    def Contains(self, keyword):
        data = ''
        for i in range(0, len(self.content)):
            if self.content[i][1] == 'stream':
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1

    def StreamContains(self, keyword, filter, casesensitive, regex):
        if not self.ContainsStream():
            return False
        streamData = self.Stream(filter)
        if filter and streamData == 'No filters':
            streamData = self.Stream(False)
        if regex:
            return re.search(keyword, streamData, IIf(casesensitive, 0, re.I))
        elif casesensitive:
            return keyword in streamData
        else:
            return keyword.lower() in streamData.lower()

    def Stream(self, filter=True):
        state = 'start'
        countDirectories = 0
        data = ''
        filters = []
        for i in range(0, len(self.content)):
            if state == 'start':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '<<':
                    countDirectories += 1
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '>>':
                    countDirectories -= 1
                if countDirectories == 1 and self.content[i][0] == CHAR_DELIMITER and EqualCanonical(
                        self.content[i][1], '/Filter'):
                    state = 'filter'
                elif countDirectories == 0 and self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                    state = 'stream-whitespace'
            elif state == 'filter':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == '/':
                    filters = [self.content[i][1]]
                    state = 'search-stream'
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '[':
                    state = 'filter-list'
            elif state == 'filter-list':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == '/':
                    filters.append(self.content[i][1])
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == ']':
                    state = 'search-stream'
            elif state == 'search-stream':
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                    state = 'stream-whitespace'
            elif state == 'stream-whitespace':
                if self.content[i][0] == CHAR_WHITESPACE:
                    whitespace = self.content[i][1]
                    if whitespace.startswith('\x0D\x0A') and len(whitespace) > 2:
                        data += whitespace[2:]
                    elif whitespace.startswith('\x0A') and len(whitespace) > 1:
                        data += whitespace[1:]
                else:
                    data += self.content[i][1]
                state = 'stream-concat'
            elif state == 'stream-concat':
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'endstream':
                    if filter:
                        return self.Decompress(data, filters)
                    else:
                        return data
                else:
                    data += self.content[i][1]
            else:
                return 'Unexpected filter state'
        return filters

    def Decompress(self, data, filters):
        for filter in filters:
            if EqualCanonical(filter, '/FlateDecode') or EqualCanonical(filter, '/Fl'):
                try:
                    data = FlateDecode(data)
                except zlib.error as e:
                    message = 'FlateDecode decompress failed'
                    if len(data) > 0 and ord(data[0]) & 0x0F != 8:
                        message += ', unexpected compression method: %02x' % ord(data[0])
                    return message + '. zlib.error %s' % e.message
            elif EqualCanonical(filter, '/ASCIIHexDecode') or EqualCanonical(filter, '/AHx'):
                try:
                    data = ASCIIHexDecode(data)
                except:
                    return 'ASCIIHexDecode decompress failed'
            elif EqualCanonical(filter, '/ASCII85Decode') or EqualCanonical(filter, '/A85'):
                try:
                    data = ASCII85Decode(data.rstrip('>'))
                except:
                    return 'ASCII85Decode decompress failed'
            elif EqualCanonical(filter, '/LZWDecode') or EqualCanonical(filter, '/LZW'):
                try:
                    data = LZWDecode(data)
                except:
                    return 'LZWDecode decompress failed'
            elif EqualCanonical(filter, '/RunLengthDecode') or EqualCanonical(filter, '/R'):
                try:
                    data = RunLengthDecode(data)
                except:
                    return 'RunLengthDecode decompress failed'


#            elif i.startswith('/CC')                        # CCITTFaxDecode
#            elif i.startswith('/DCT')                       # DCTDecode
            else:
                return 'Unsupported filter: %s' % repr(filters)
        if len(filters) == 0:
            return 'No filters'
        else:
            return data

    def StreamYARAMatch(self, rules, decoders, decoderoptions, filter):
        if not self.ContainsStream():
            return None
        streamData = self.Stream(filter)
        if filter and streamData == 'No filters':
            streamData = self.Stream(False)

        oDecoders = [cIdentity(streamData, None)]
        for cDecoder in decoders:
            try:
                oDecoder = cDecoder(streamData, decoderoptions)
                oDecoders.append(oDecoder)
            except Exception as e:
                print('Error instantiating decoder: %s' % cDecoder.name)
                raise e
        results = []
        for oDecoder in oDecoders:
            while oDecoder.Available():
                yaraResults = rules.match(data=oDecoder.Decode())
                if yaraResults != []:
                    results.append([oDecoder.Name(), yaraResults])

        return results


class cPDFElementStartxref:

    def __init__(self, index):
        self.type = PDF_ELEMENT_STARTXREF
        self.index = index


class cPDFElementMalformed:

    def __init__(self, content):
        self.type = PDF_ELEMENT_MALFORMED
        self.content = content


def TrimLWhiteSpace(data):
    while data != [] and data[0][0] == CHAR_WHITESPACE:
        data = data[1:]
    return data


def TrimRWhiteSpace(data):
    while data != [] and data[-1][0] == CHAR_WHITESPACE:
        data = data[:-1]
    return data


class cPDFParseDictionary:

    def __init__(self, content, nocanonicalizedoutput):
        self.content = content
        self.nocanonicalizedoutput = nocanonicalizedoutput
        dataTrimmed = TrimLWhiteSpace(TrimRWhiteSpace(self.content))
        if dataTrimmed == []:
            self.parsed = None
        elif self.isOpenDictionary(dataTrimmed[0]) and (self.isCloseDictionary(dataTrimmed[-1]) or
                                                        self.couldBeCloseDictionary(dataTrimmed[-1])):
            self.parsed = self.ParseDictionary(dataTrimmed)[0]
        else:
            self.parsed = None

    def isOpenDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == '<<'

    def isCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == '>>'

    def couldBeCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1].rstrip().endswith('>>')

    def ParseDictionary(self, tokens):
        state = 0  # start
        dictionary = []
        while tokens != []:
            if state == 0:
                if self.isOpenDictionary(tokens[0]):
                    state = 1
                else:
                    return None, tokens
            elif state == 1:
                if self.isOpenDictionary(tokens[0]):
                    pass
                elif self.isCloseDictionary(tokens[0]):
                    return dictionary, tokens
                elif tokens[0][0] != CHAR_WHITESPACE:
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
            elif state == 2:
                if self.isOpenDictionary(tokens[0]):
                    value, tokens = self.ParseDictionary(tokens)
                    dictionary.append((key, value))
                    state = 1
                elif self.isCloseDictionary(tokens[0]):
                    dictionary.append((key, value))
                    return dictionary, tokens
                elif value == [] and tokens[0][0] == CHAR_WHITESPACE:
                    pass
                elif value == [] and tokens[0][1] == '[':
                    value.append(tokens[0][1])
                elif value != [] and value[0] == '[' and tokens[0][1] != ']':
                    value.append(tokens[0][1])
                elif value != [] and value[0] == '[' and tokens[0][1] == ']':
                    value.append(tokens[0][1])
                    dictionary.append((key, value))
                    value = []
                    state = 1
                elif value == [] and tokens[0][1] == '(':
                    value.append(tokens[0][1])
                elif value != [] and value[0] == '(' and tokens[0][1] != ')':
                    if tokens[0][1][0] == '%':
                        tokens = [tokens[0]] + cPDFTokenizer(StringIO(tokens[0][1][1:])).Tokens() + tokens[1:]
                        value.append('%')
                    else:
                        value.append(tokens[0][1])
                elif value != [] and value[0] == '(' and tokens[0][1] == ')':
                    value.append(tokens[0][1])
                    dictionary.append((key, value))
                    value = []
                    state = 1
                elif value != [] and tokens[0][1][0] == '/':
                    dictionary.append((key, value))
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
                else:
                    value.append(ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput))
            tokens = tokens[1:]

    def Retrieve(self):
        return self.parsed

    def PrettyPrintSubElement(self, prefix, e):
        res = ""
        if e[1] == []:
            res += '%s  %s' % (prefix, e[0])
        elif type(e[1][0]) == type(''):
            if len(e[1]) == 3 and IsNumeric(e[1][0]) and e[1][1] == '0' and e[1][2] == 'R':
                joiner = ' '
            else:
                joiner = ''
            value = joiner.join(e[1]).strip()
            reprValue = repr(value)
            if "'" + value + "'" != reprValue:
                value = reprValue
            res += '%s  %s %s' % (prefix, e[0], value)
        else:
            res += '%s  %s' % (prefix, e[0])
            sres = self.PrettyPrintSub(prefix + '    ', e[1])
            res += sres
        return res

    def PrettyPrintSub(self, prefix, dictionary):
        res = ""
        if dictionary != None:
            res = '<<++<<'
            for e in dictionary:
                sres = self.PrettyPrintSubElement(prefix, e)
                res += sres
            res += '>>++>>'
        return res

    def PrettyPrint(self, prefix):
        res = self.PrettyPrintSub(prefix, self.parsed)
        return res

    def Get(self, select):
        for key, value in self.parsed:
            if key == select:
                return value
        return None

    def GetNestedSub(self, dictionary, select):
        for key, value in dictionary:
            if key == select:
                return self.PrettyPrintSubElement('', [select, value])
            if type(value) == type([]) and len(value) > 0 and type(value[0]) == type((None,)):
                result = self.GetNestedSub(value, select)
                if result != None:
                    return self.PrettyPrintSubElement('', [select, result])
        return None

    def GetNested(self, select):
        return self.GetNestedSub(self.parsed, select)


def FormatOutput(data, raw):
    if raw:
        if type(data) == type([]):
            return ''.join(map(lambda x: x[1], data))
        else:
            return data
    else:
        return repr(data)


#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(data)
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]


def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)


def PrintOutputObject(object, filt, nocanonicalizedoutput, dump, show_stream=False, hsh=False, raw=False):
    errors = set()
    res = ""
    res += 'obj %d %d\n' % (object.id, object.version)
    res += 'Type: %s\n' % ConditionalCanonicalize(object.GetType(), nocanonicalizedoutput)
    res += 'Referencing: %s\n' % ', '.join(map(lambda x: '%s %s %s' % x, object.GetReferences()))
    dataPrecedingStream = object.ContainsStream()
    oPDFParseDictionary = None
    if dataPrecedingStream:
        res += 'Contains stream\n'
        oPDFParseDictionary = cPDFParseDictionary(dataPrecedingStream, nocanonicalizedoutput)
        if hsh:
            streamContent = object.Stream(False)
            res += 'unfiltered\n'
            res += 'len: %6d md5: %s\n' % (len(streamContent), hashlib.md5(streamContent).hexdigest())
            res += '%s\n' % HexAsciiDumpLine(streamContent)
            streamContent = object.Stream(True)
            res += 'filtered\n'
            res += 'len: %6d md5: %s\n' % (len(streamContent), hashlib.md5(streamContent).hexdigest())
            res += '%s\n' % HexAsciiDumpLine(streamContent)
            streamContent = None
    else:
        if raw:
            res += '%s\n' % FormatOutput(object.content, raw)
        oPDFParseDictionary = cPDFParseDictionary(object.content, nocanonicalizedoutput)
    if show_stream:
        res += oPDFParseDictionary.PrettyPrint('  ')
    if filt:
        filtered = object.Stream()
        if filtered == []:
            res += ('%s\n' % FormatOutput(object.content, raw))
        else:
            res += ('%s\n' % FormatOutput(filtered, raw))
    if dump:
        filtered = object.Stream(filt == True)
        if filtered == []:
            filtered = ''
        fdata = C2BIP3(filtered)
        if fdata.startswith('Unsupported filter: '):
            errors.add(fdata)
        elif len(fdata) > 10:
            try:
                with open(dump, 'wb') as f:
                    f.write(fdata)
                res += "Object extracted. See extracted files."
            except:
                errors.add('Error writing file %s' % dump)
    return res, errors


def Canonicalize(sIn):
    if sIn == '':
        return sIn
    elif sIn[0] != '/':
        return sIn
    elif sIn.find('#') == -1:
        return sIn
    else:
        i = 0
        iLen = len(sIn)
        sCanonical = ''
        while i < iLen:
            if sIn[i] == '#' and i < iLen - 2:
                try:
                    sCanonical += chr(int(sIn[i + 1:i + 3], 16))
                    i += 2
                except:
                    sCanonical += sIn[i]
            else:
                sCanonical += sIn[i]
            i += 1
        return sCanonical


def EqualCanonical(s1, s2):
    return Canonicalize(s1) == s2


def ConditionalCanonicalize(sIn, nocanonicalizedoutput):
    if nocanonicalizedoutput:
        return sIn
    else:
        return Canonicalize(sIn)


# http://code.google.com/p/pdfminerr/source/browse/trunk/pdfminer/pdfminer/ascii85.py
def ASCII85Decode(data):
    import struct
    n = b = 0
    out = ''
    for c in data:
        if '!' <= c and c <= 'u':
            n += 1
            b = b * 85 + (ord(c) - 33)
            if n == 5:
                out += struct.pack('>L', b)
                n = b = 0
        elif c == 'z':
            assert n == 0
            out += '\0\0\0\0'
        elif c == '~':
            if n:
                for _ in range(5 - n):
                    b = b * 85 + 84
                out += struct.pack('>L', b)[:n - 1]
            break
    return out


def ASCIIHexDecode(data):
    return binascii.unhexlify(''.join([c for c in data if c not in ' \t\n\r']).rstrip('>'))


# if inflating fails, we try to inflate byte per byte (sample 4da299d6e52bbb79c0ac00bad6a1d51d4d5fe42965a8d94e88a359e5277117e2)
def FlateDecode(data):
    try:
        return zlib.decompress(C2BIP3(data))
    except:
        if len(data) <= 10:
            raise
        oDecompress = zlib.decompressobj()
        oStringIO = StringIO()
        count = 0
        for byte in C2BIP3(data):
            try:
                oStringIO.write(oDecompress.decompress(byte))
                count += 1
            except:
                break
        if len(data) - count <= 2:
            return oStringIO.getvalue()
        else:
            raise


def RunLengthDecode(data):
    f = StringIO(data)
    decompressed = ''
    runLength = ord(f.read(1))
    while runLength:
        if runLength < 128:
            decompressed += f.read(runLength + 1)
        if runLength > 128:
            decompressed += f.read(1) * (257 - runLength)
        if runLength == 128:
            break
        runLength = ord(f.read(1))
#    return sub(r'(\d+)(\D)', lambda m: m.group(2) * int(m.group(1)), data)
    return decompressed


#### LZW code sourced from pdfminer
# Copyright (c) 2004-2009 Yusuke Shinyama <yusuke at cs dot nyu dot edu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:


class LZWDecoder(object):

    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8 - self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v << bits) | ((self.buff >> (r - bits)) & ((1 << bits) - 1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v << r) | (self.buff & ((1 << r) - 1))
                bits -= r
                x = self.fp.read(1)
                if not x: raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ''
        if code == 256:
            self.table = [chr(c) for c in range(256)]  # 0-255
            self.table.append(None)  # 256
            self.table.append(None)  # 257
            self.prevbuf = ''
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf + x[0])
            else:
                self.table.append(self.prevbuf + self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
        return


####


def LZWDecode(data):
    return ''.join(LZWDecoder(StringIO(data)).run())


def PrintGenerateObject(object, options, newId=None):
    if newId == None:
        objectId = object.id
    else:
        objectId = newId
    dataPrecedingStream = object.ContainsStream()
    if dataPrecedingStream:
        if options.filter:
            decompressed = object.Stream(True)
            if decompressed == 'No filters' or decompressed.startswith('Unsupported filter: '):
                print('    oPDF.stream(%d, %d, %s, %s)' %
                      (objectId, object.version, repr(object.Stream(False).rstrip()),
                       repr(re.sub('/Length\s+\d+', '/Length %d', FormatOutput(dataPrecedingStream, True)).strip())))
            else:
                dictionary = FormatOutput(dataPrecedingStream, True)
                dictionary = re.sub(r'/Length\s+\d+', '', dictionary)
                dictionary = re.sub(r'/Filter\s*/[a-zA-Z0-9]+', '', dictionary)
                dictionary = re.sub(r'/Filter\s*\[.+\]', '', dictionary)
                dictionary = re.sub(r'^\s*<<', '', dictionary)
                dictionary = re.sub(r'>>\s*$', '', dictionary)
                dictionary = dictionary.strip()
                print("    oPDF.stream2(%d, %d, %s, %s, 'f')" % (objectId, object.version, repr(decompressed.rstrip()),
                                                                 repr(dictionary)))
        else:
            print('    oPDF.stream(%d, %d, %s, %s)' %
                  (objectId, object.version, repr(object.Stream(False).rstrip()),
                   repr(re.sub('/Length\s+\d+', '/Length %d', FormatOutput(dataPrecedingStream, True)).strip())))
    else:
        print('    oPDF.indirectobject(%d, %d, %s)' % (objectId, object.version,
                                                       repr(FormatOutput(object.content, True).strip())))


def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line: line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()


def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]


def YARACompile(ruledata):
    if ruledata.startswith('#'):
        if ruledata.startswith('#h#'):
            rule = binascii.a2b_hex(ruledata[3:])
        elif ruledata.startswith('#b#'):
            rule = binascii.a2b_base64(ruledata[3:])
        elif ruledata.startswith('#s#'):
            rule = 'rule string {strings: $a = "%s" ascii wide nocase condition: $a}' % ruledata[3:]
        elif ruledata.startswith('#q#'):
            rule = ruledata[3:].replace("'", '"')
        else:
            rule = ruledata[1:]
        return yara.compile(source=rule)
    else:
        dFilepaths = {}
        if os.path.isdir(ruledata):
            for root, dirs, files in os.walk(ruledata):
                for file in files:
                    filename = os.path.join(root, file)
                    dFilepaths[filename] = filename
        else:
            for filename in ProcessAt(ruledata):
                dFilepaths[filename] = filename
        return yara.compile(filepaths=dFilepaths)


def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)


class cDecoderParent():
    pass


def LoadDecoders(decoders, verbose):
    if decoders == '':
        return
    scriptPath = os.path.dirname(sys.argv[0])
    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec(open(decoder, 'r').read(), globals(), globals())
        except Exception as e:
            print('Error loading decoder: %s' % decoder)
            if verbose:
                raise e


class cIdentity(cDecoderParent):
    name = 'Identity function decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self.available = True

    def Available(self):
        return self.available

    def Decode(self):
        self.available = False
        return self.stream

    def Name(self):
        return ''


def DecodeFunction(decoders, options, stream):
    if decoders == []:
        return stream
    return decoders[0](stream, options.decoderoptions).Decode()


class cDumpStream():

    def __init__(self):
        self.text = ''

    def Addline(self, line):
        if line != '':
            self.text += line + '\n'

    def Content(self):
        return self.text


def HexDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0 and hexDump != '':
            oDumpStream.Addline(hexDump)
            hexDump = ''
        hexDump += IFF(hexDump == '', '', ' ') + '%02X' % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()


def CombineHexAscii(hexDump, asciiDump):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (dumplinelength - len(asciiDump)))) + asciiDump


def HexAsciiDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    asciiDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0:
            if hexDump != '':
                oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
            hexDump = '%08X:' % i
            asciiDump = ''
        hexDump += ' %02X' % ord(b)
        asciiDump += IFF(ord(b) >= 32, b, '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()


def HexAsciiDumpLine(data):
    return HexAsciiDump(data[0:16])[10:-1]


def PDFParserMain(filename, outdirectory, **kwargs):
    """
    Modified by CSE to fit ASSEMBLYLINE Service
    """
    """
    pdf-parser, use it to parse a PDF document
    """

    # Options
    verbose = kwargs.get("verbose", False)
    filt = kwargs.get("filter", False)
    search = kwargs.get("search", None)
    obj = kwargs.get("object", None)
    typ = kwargs.get("type", None)
    reference = kwargs.get("reference", None)
    searchstream = kwargs.get("searchstream", None)
    stats = kwargs.get("stats", False)
    key = kwargs.get("key", None)
    raw = kwargs.get("raw", False)
    hsh = kwargs.get("hash", False)
    dump = kwargs.get("dump", None)
    get_object_detail = kwargs.get("get_object_detail", False)
    get_malform = kwargs.get("get_malform", True)
    max_objstm = kwargs.get("max_objstm", 100)

    if dump:
        dump = os.path.join(outdirectory, dump)
    elements = kwargs.get("elements", None)
    nocanonicalizedoutput = kwargs.get("nocanonicalizedoutput", False)

    malform_content = os.path.join(outdirectory, "malformed_content")

    max_search_hits = 50
    search_hits = 0

    try:
        oPDFParser = cPDFParser(filename, verbose=verbose, extract=malform_content)
    except Exception as e:
        raise Exception(e)
    cntComment = 0
    cntXref = 0
    cntTrailer = 0
    cntStartXref = 0
    cntIndirectObject = 0
    dicObjectTypes = {}

    selectComment = False
    selectXref = False
    selectTrailer = False
    selectStartXref = False
    selectIndirectObject = False
    show_stream = False
    if elements:
        for c in elements:
            if c == 'c':
                selectComment = True
            elif c == 'x':
                selectXref = True
            elif c == 't':
                selectTrailer = True
            elif c == 's':
                selectStartXref = True
            elif c == 'i':
                selectIndirectObject = True
            else:
                print('Error: unknown --elements value %s' % c)
                return
    else:
        selectIndirectObject = True
        if not search and not obj and not reference and not typ and not searchstream and not key:
            selectComment = True
            selectXref = True
            selectTrailer = True
            selectStartXref = True
        if search or key:
            selectTrailer = True
            show_stream = True

    optionsType = ''
    if typ:
        optionsType = typ

    results = {
        'version': __version__,
        'parts': [],
        'stats': [],
        'files': {
            'embedded': [],
            'malformed': [],
            'triage_kw': []
        },
        'obj_details': ""
    }
    errors = set()

    while True:
        try:
            object = oPDFParser.GetObject()
        except Exception:
            continue
        if object != None:
            if stats:
                if object.type == PDF_ELEMENT_COMMENT:
                    cntComment += 1
                elif object.type == PDF_ELEMENT_XREF:
                    cntXref += 1
                elif object.type == PDF_ELEMENT_TRAILER:
                    cntTrailer += 1
                elif object.type == PDF_ELEMENT_STARTXREF:
                    cntStartXref += 1
                elif object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                    cntIndirectObject += 1
                    type1 = object.GetType()
                    if not type1 in dicObjectTypes:
                        dicObjectTypes[type1] = [object.id]
                    else:
                        dicObjectTypes[type1].append(object.id)

            else:
                if object.type == PDF_ELEMENT_COMMENT and selectComment:
                    if not search and not key or search and object.Contains(search):
                        results['parts'].append('PDF Comment %s' % FormatOutput(object.comment, raw))
                elif object.type == PDF_ELEMENT_XREF and selectXref:
                    results['parts'].append('xref %s' % FormatOutput(object.content, raw))
                elif object.type == PDF_ELEMENT_TRAILER and selectTrailer:
                    oPDFParseDictionary = cPDFParseDictionary(object.content[1:], nocanonicalizedoutput)
                    if not search and not key or search and object.Contains(search):
                        if oPDFParseDictionary == None:
                            results['parts'].append('trailer: %s' % FormatOutput(object.content, raw))
                        else:
                            trailer = 'trailer:\n'
                            trailer += oPDFParseDictionary.PrettyPrint('  ')
                            results['parts'].append(trailer)
                    elif key:
                        if oPDFParseDictionary.parsed != None:
                            result = oPDFParseDictionary.GetNested(key)
                            if result != None:
                                results['parts'].append(result)
                elif object.type == PDF_ELEMENT_STARTXREF and selectStartXref:
                    if not search:
                        results['parts'].append('startxref %d' % object.index)
                elif object.type == PDF_ELEMENT_INDIRECT_OBJECT and selectIndirectObject:
                    if search:
                        if search_hits <= max_search_hits:
                            if object.Contains(search):
                                res, err = PrintOutputObject(
                                    object,
                                    filt,
                                    nocanonicalizedoutput,
                                    dump,
                                    raw=raw,
                                    hsh=hsh,
                                    show_stream=show_stream)
                                if search in res:
                                    results['parts'].append(res)
                                    search_hits += 1
                                else:
                                    # Try again, this time getting the raw output
                                    res, err = PrintOutputObject(object, filt, nocanonicalizedoutput, dump, raw=True)
                                    if search in res:
                                        results['parts'].append(res)
                                        search_hits += 1
                        else:
                            break
                    elif key:
                        oPDFParseDictionary = cPDFParseDictionary(object.content[1:], nocanonicalizedoutput)
                        if oPDFParseDictionary.parsed != None:
                            result = oPDFParseDictionary.GetNested(key)
                            if result != None:
                                results['parts'].append(result)
                    elif obj:
                        if object.id == eval(obj):
                            res, err = PrintOutputObject(
                                object, filt, nocanonicalizedoutput, dump, raw=raw, hsh=hsh, show_stream=show_stream)
                            results['parts'].append(res)
                            if get_object_detail:
                                obj_det = re.match(r'[\r]?\n<<.+>>[\r]?\n', FormatOutput(object.content, raw=True),
                                                   re.DOTALL)
                                if obj_det:
                                    results['obj_details'] = obj_det.group(0)
                            if dump and "Object extracted." in res:
                                results['files']['embedded'].append(dump)
                            if len(err) > 0:
                                for e in err:
                                    errors.add("Object extraction error: {}".format(e))
                            break
                    elif reference:
                        if object.References(reference):
                            res, err = PrintOutputObject(
                                object, filt, nocanonicalizedoutput, dump, raw=raw, hsh=hsh, show_stream=show_stream)
                            results['parts'].append(res)
                    elif typ:
                        if EqualCanonical(object.GetType(), optionsType):
                            if search_hits <= max_objstm:
                                res, err = PrintOutputObject(
                                    object,
                                    filt,
                                    nocanonicalizedoutput,
                                    dump,
                                    raw=raw,
                                    hsh=hsh,
                                    show_stream=show_stream)
                                results['parts'].append(res)
                                search_hits += 1
                            else:
                                break
                    elif hsh:
                        results['parts'].append('obj %d %d' % (object.id, object.version))
                        rawContent = FormatOutput(object.content, True)
                        results['parts'].append(
                            ' len: %d md5: %s' % (len(rawContent), hashlib.md5(rawContent).hexdigest()))
                    else:
                        res, err = PrintOutputObject(
                            object, filt, nocanonicalizedoutput, dump, raw=raw, hsh=hsh, show_stream=show_stream)
                        results['parts'].append(res)
                elif object.type == PDF_ELEMENT_MALFORMED and get_malform:
                    if len(object.content) > 50:
                        try:
                            with open(malform_content, 'wb') as fExtract:
                                fExtract.write(C2BIP3(object.content))
                            results['files']['malformed'].append(malform_content)
                        except:
                            errors.add('Error writing file %s' % malform_content)
        else:
            break

    if stats:
        results['stats'].append('Comment: %s' % cntComment)
        results['stats'].append('XREF: %s' % cntXref)
        results['stats'].append('Trailer: %s' % cntTrailer)
        results['stats'].append('StartXref: %s' % cntStartXref)
        results['stats'].append('Indirect object: %s' % cntIndirectObject)
        names = dicObjectTypes.keys()
        names.sort()
        for key in names:
            results['stats'].append(
                '%s %d: %s' % (key, len(dicObjectTypes[key]), ', '.join(map(lambda x: '%d' % x, dicObjectTypes[key]))))
    return results, errors


def TestPythonVersion(enforceMaximumVersion=False, enforceMinimumVersion=False):
    if sys.version_info[0:3] > __maximum_python_version__:
        if enforceMaximumVersion:
            print('This program does not work with this version of Python (%d.%d.%d)' % sys.version_info[0:3])
            print('Please use Python version %d.%d.%d' % __maximum_python_version__)
            sys.exit()
        else:
            print('This program has not been tested with this version of Python (%d.%d.%d)' % sys.version_info[0:3])
            print('Should you encounter problems, please use Python version %d.%d.%d' % __maximum_python_version__)
    if sys.version_info[0:3] < __minimum_python_version__:
        if enforceMinimumVersion:
            print('This program does not work with this version of Python (%d.%d.%d)' % sys.version_info[0:3])
            print('Please use Python version %d.%d.%d' % __maximum_python_version__)
            sys.exit()
        else:
            print('This program has not been tested with this version of Python (%d.%d.%d)' % sys.version_info[0:3])
            print('Should you encounter problems, please use Python version %d.%d.%d' % __maximum_python_version__)
