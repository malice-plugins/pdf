# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

__description__ = 'Malice PDF Plugin - pdf-parser.py helper util'
__author__ = 'blacktop - <https://github.com/blacktop>'
__version__ = '0.1.0'
__date__ = '2018/07/21'
__credit__ = 'Modified from https://bitbucket.org/cse-assemblyline/alsvc_pdfid'

import logging
import re
import unicodedata
from os import path

from . import pdf_parser as pdfparser
from .balbuzard.patterns import PatternMatch


class MalPdfParser(object):

    def __init__(self, file_path, working_dir, pdfid_results, max_extract=5, verbose=0):
        self.file_path = file_path
        self.working_dir = working_dir
        self.pdfid_results = pdfid_results
        self.max_extract = max_extract
        self.all_errors = set()
        self.log = logging.getLogger(__name__)
        self.log.setLevel(verbose)

        if not path.exists(self.file_path):
            raise Exception("file does not exist: {}".format(self.file_path))
        if not path.isdir(self.working_dir):
            raise Exception("extraction path does not exist: {}".format(self.working_dir))

        self.parse_pdfid_results(pdfid_results)

    def parse_pdfid_results(self, results):
        for key in results['keywords'].get('keyword'):
            if '/EmbeddedFile' in key.get('name') and key.get('count') > 0:
                self.embed_present = True
            if '/ObjStm' in key.get('name') and key.get('count') > 0:
                self.objstms = True

    @staticmethod
    def get_pdfparser(file_path, working_dir, options):
        try:
            pdfparser_statresult, errors = pdfparser.PDFParserMain(file_path, working_dir, **options)
        except Exception as e:
            raise Exception("PDFParser failed to run on sample. Error: {}".format(e))

        return pdfparser_statresult, errors

    def write_objstm(self, file_path, working_dir, objstm, objstm_path):
        """

        :param file_path:
        :param working_dir:
        :param objstm:
        :param objstm_path:
        :return:
        """

        stream_present = False
        header = "%PDF-1.5\x0A%Fake header created by AL PDFID service.\x0A"
        trailer = "%%EOF\x0A"
        obj_footer = "endobj\x0A"
        objstm_file = None

        options = {
            "object": objstm,
            "dump": objstm_path,
            "filter": True,
            "raw": True,
        }
        try:
            pdfparser_subresult, _ = self.get_pdfparser(file_path, working_dir, options)
        except Exception as e:
            pdfparser_subresult = None
            self.log.debug(e)

        if pdfparser_subresult:
            for sub_p in pdfparser_subresult['parts']:
                if sub_p.split("\n", 4)[3] == "Contains stream":
                    stream_present = True
            if stream_present:
                files = pdfparser_subresult.get("files", None)
                if files:
                    for fi, l in files.iteritems():
                        if fi == 'embedded' and len(l) > 0:
                            objstm_file = l[0]
                            with open(objstm_file, 'r+') as f:
                                stream = f.read()
                                # Remove any extra content before objects
                                if not re.match("<<.*", stream):
                                    extra_content = re.match(r'[^<]*', stream).group(0)
                                    stream = stream.replace(extra_content, "%{}\x0A".format(extra_content))
                                # Find all labels and surround them with obj headers
                                obj_idx = 1
                                for m in re.findall(r"(<<[^\n]*>>\x0A|<<[^\n]*>>$)", stream):
                                    stream = stream.replace(m, "{} 0 obj\x0A".format(obj_idx) + m + obj_footer)
                                    obj_idx += 1
                                f.seek(0, 0)
                                f.write(header + stream + trailer)

        return objstm_file

    def analyze_objstm(self, file_path, working_dir, extract_count=1):
        """

        :param file_path:
        :param working_dir:
        :param extract_count:
        :return:
        """

        objstm_extracted = set()

        obj_files = set()

        # NOTE: an extract_count of 1 is really 2
        options_objstm = {"elements": "i", "type": "/ObjStm", "max_objstm": extract_count}

        try:
            pdfparser_result, _ = self.get_pdfparser(file_path, working_dir, options_objstm)
            parts = pdfparser_result.get("parts", None)
        except Exception as e:
            parts = None
            self.log.debug(e)
        if parts:
            idx = 0
            for p in sorted(parts):
                if "Type: /ObjStm" in p:
                    getobj = p.split("\n", 1)[0].split(" ")[1]
                    if getobj in objstm_extracted:
                        continue
                    dump_file = path.join(self.working_dir, "objstm_{0}_{1}".format(getobj, idx))
                    idx += 1
                    obj_file = self.write_objstm(file_path, working_dir, getobj, dump_file)
                    if obj_file:
                        objstm_extracted.add(getobj)
                        obj_files.add(obj_file)

        return obj_files

    def analyze(self, file_path, working_dir, get_malform=True):
        """Analyze PDF with pdf-parser.py to extract embedded objects

        :param file_path:
        :param working_dir:
        :param get_malform:
        :return:
        """
        triage_keywords = set()
        # embed_present = False
        objstms = False
        tags = set()

        # if plugin:
        #     # If any plugin results, run pdfparse
        #     run_pdfparse = True
        #     plres = ResultSection(title_text="Plugin Results", score=SCORE.NULL, parent=pdfidres)
        #     for pllist in plugin:

        #     # Grab suspicious properties for pdfparser
        #     if pllist[0] == 'Triage':
        #         triage_keywords.update(
        #             [re.sub(r'(\"|:|/)', '', x) for x in re.findall(r'\"/[^\"]*\":', pllist[2], re.IGNORECASE)])

        ##############################################
        # PARSE PDFiD output                         #
        ##############################################
        keywords = ('/JS', '/JavaScript', '/AA', '/OpenAction', '/AcroForm', '/JBIG2Decode', '/RichMedia', '/Launch',
                    '/EmbeddedFile', '/XFA', '/Colors > 2^24', '/Encrypt', '/Annot', '/ObjStm', '/URI')
        for key in self.pdfid_results['keywords'].get('keyword'):
            if '/EmbeddedFile' in key.get('name') and key.get('count') > 0:
                embed_present = True
            if '/ObjStm' in key.get('name') and key.get('count') > 0:
                objstms = True
            if key.get('name') in keywords and key.get('count') > 0:
                triage_keywords.add(key.get('name').lstrip('/').strip())
            # TODO ?!?!?!?!?!?! +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            # TODO: IF TRIAGE KEYWORDS FOUND ADD THEM, I COULD JUST GREP FOR THEM NOW
            # if flist[0] in additional_keywords:
            #     triage_keywords.add(flist[0].replace("/", "", 1))

        # CALL PDF parser and extract further information
        self.log.debug("PDF Parser Results")
        # STATISTICS
        # Do not run for objstms, which are being analyzed when get_malform == False
        if get_malform:
            options = {
                "stats": True,
            }
            try:
                pdfparser_result, errors = self.get_pdfparser(file_path, working_dir, options)
            except Exception as e:
                pdfparser_result = None
                self.log.debug(e)

            if pdfparser_result:
                if len(pdfparser_result) == 0:
                    self.log.debug("No statistical results generated for file. Please see errors.")
                else:
                    # TODO: OUTPUT STATS TO JSON ==================================================<<<<<<<<<<<<<<<<
                    stats = pdfparser_result.get("stats", None)
                    if stats:
                        self.log.debug("PDF Statistcs:")
                        for p in stats:
                            self.log.debug("{}".format(p))
                for e in errors:
                    self.all_errors.add(e)

        # Triage plugin -- search sample for keywords and carve content or extract object (if it contains a stream)
        carved_content = {}  # Format { "objnum": [{keyword: content list}}
        obj_extract_triage = set()
        jbig_objs = set()

        for keyword in triage_keywords:

            self.log.debug('TAG: FILE_STRING')
            # ObjStms handled differently
            if keyword == 'ObjStm':
                continue

            options = {
                "search": keyword,
            }
            try:
                pdfparser_result, errors = self.get_pdfparser(file_path, working_dir, options)
            except Exception as e:
                pdfparser_result = None
                self.log.debug(e)

            if pdfparser_result:
                for p in pdfparser_result['parts']:
                    content = ""
                    references = []
                    # Trailer will be extracted anyways, try and grab all references anyways -- will be messy
                    if p.startswith("trailer:"):
                        # Grab the content after the keyword
                        # Check that keyword actually in content
                        if "/{}".format(keyword) in p:
                            try:
                                content = p.split(keyword, 1)[1].replace('>>++>>', '').split("/", 1)[0].strip()
                                references = re.findall("[0-9]* [0-9]* R", content)
                            except Exception:
                                continue
                    # If not trailer, should be object
                    elif 'Referencing:' in p:
                        # Grab the content after the keyword
                        if '>>++>>' in p:
                            try:
                                content = p.split(keyword, 1)[1].replace('>>++>>', '').strip()
                            except Exception:
                                try:
                                    content = p.split("\n", 3)[3]
                                except Exception:
                                    content = p
                        else:
                            try:
                                content = p.split("\n", 3)[3]
                            except Exception:
                                content = p
                        # Sometimes the content is the same keyword with references (i.e "/URI /URI 10 0 R"
                        if content.startswith("/{}".format(keyword)):
                            try:
                                content = re.sub("/{}[ ]*".format(keyword), "", content, 1)
                            except Exception:
                                pass
                        try:
                            references = p.split("\n", 3)[2].replace('Referencing:', '').strip().split(", ")
                        except Exception:
                            pass
                    # Special condition for JBIG2Decode
                    if keyword == "JBIG2Decode" and "/Filter" in p and "Contains stream" in p:
                        try:
                            objnum = p.split("\n", 1)[0].split(" ")[1]
                            obj_extract_triage.add(objnum)
                            jbig_objs.add(objnum)
                            continue
                        except Exception as e:
                            self.log.debug(e)
                            continue
                    # If no content, then keyword likely points to reference objects, so grab those
                    if content == '':
                        if len(references) > 0:
                            content = references
                        else:
                            # Something is wrong, drop it.
                            continue
                    else:
                        while True:
                            # Multiple references might be in a list, i.e. /Annot # # R vs. /Annots [# # R # # R]
                            islist = re.match(r"[s]?[ ]?\[([0-9]* [0-9]* R[ \\rn]{0,8})*\]", content)
                            if islist:
                                content = re.sub(r"\[|\]", "",
                                                 islist.group(0).replace("s ", '').replace("R ", "R,")).split(",")
                                break
                            # References might be with instructions, i.e. [# # R /FitH null]
                            withinst = re.match(
                                r"[s]?[ \\']{0,3}\[[ ]?([0-9]* [0-9]* R)[ \\rn]{1,8}"
                                r"[/a-zA-Z0-9 ]*[ ]?\]", content)
                            if withinst:
                                content = [withinst.group(1)]
                                break
                            content = [content]
                            break
                    for c in content:
                        # If keyword = Javascript and content starts with '/JS', disregard as 'JS' will be extracted
                        if "JS" in triage_keywords and keyword == "JavaScript" and "/JS" in c[0:5]:
                            continue
                        if c in references or re.match("[0-9]* [0-9]* R", c):
                            try:
                                ref_obj = c.split(" ", 1)[0]
                                options = {"object": ref_obj, "get_object_detail": True}
                                try:
                                    pdfparser_subresult, err = self.get_pdfparser(file_path, working_dir, options)
                                except Exception as e:
                                    pdfparser_subresult = None
                                    err = []
                                    self.log.debug(e)

                                if pdfparser_subresult:
                                    for sub_p in pdfparser_subresult['parts']:
                                        sub_references = sub_p.split("\n", 3)[2].replace('Referencing:', '')\
                                            .strip().split(", ")
                                        ptyp = sub_p.split("\n", 2)[1].replace('Type:', '').strip().replace("/", "")
                                        # If the object contains a stream, extract the object.
                                        if "Contains stream" in sub_p:
                                            try:
                                                objnum = sub_p.split("\n", 1)[0].split(" ")[1]
                                                obj_extract_triage.add(objnum)
                                            except Exception:
                                                pass
                                        # Or if the object Type is the keyword, grab all referenced objects.
                                        elif sub_references[0] != '' and len(sub_references) >= 1 \
                                                and ptyp == keyword:
                                            for sr in sub_references:
                                                try:
                                                    objnum = sr.split(" ", 1)[0]
                                                    obj_extract_triage.add(objnum)
                                                except Exception:
                                                    pass
                                        # If not, extract object detail in to carved output
                                        elif pdfparser_subresult['obj_details'] != "":
                                            try:
                                                objnum = sub_p.split("\n", 1)[0].split(" ")[1]
                                                if objnum in carved_content:
                                                    carved_content[objnum]\
                                                        .append({keyword: pdfparser_subresult['obj_details']})
                                                else:
                                                    carved_content[objnum] = \
                                                        [{keyword: pdfparser_subresult['obj_details']}]
                                            except Exception:
                                                continue

                                for e in err:
                                    errors.add(e)
                            except Exception:
                                # If none of that work, just extract the original object for examination.
                                try:
                                    objnum = p.split("\n", 1)[0].split(" ")[1]
                                    obj_extract_triage.add(objnum)
                                except Exception:
                                    pass
                        # If content does not look like a reference:
                        else:
                            if p.startswith("trailer:"):
                                continue
                            objnum = p.split("\n", 1)[0].split(" ")[1]
                            # If the object contains a stream extract the object
                            if p.split("\n", 4)[3] == "Contains stream":
                                obj_extract_triage.add(objnum)
                            else:
                                # Or just carve the content
                                if objnum in carved_content:
                                    carved_content[objnum].append({keyword: c})
                                else:
                                    carved_content[objnum] = [{keyword: c}]

                for e in errors:
                    self.all_errors.add(e)

        # Add carved content to result output
        if len(carved_content) > 0 or len(jbig_objs) > 0:
            self.log.debug("===> Content of Interest <===")

        if len(jbig_objs) > 0:
            self.log.debug("The following Object IDs were extracted unfiltered as " "JBIG2Decode keyword detected:")
            for jo in jbig_objs:
                self.log.debug(" * {}".format(jo))
        if len(carved_content) > 0:
            for k, l in sorted(carved_content.iteritems()):
                carved_obj_idx = 0
                for d in l:
                    for keyw, con in d.iteritems():
                        self.log.debug("Content for Keyword hit from Object {0}:  '{1}':".format(k, keyw))
                        # TODO: make this value configurable
                        if len(con) < 50:
                            self.log.debug("carved_content: {}".format(con))
                            # subres.add_line(con)
                            # Check for IOC content
                            try:
                                patterns = PatternMatch()
                            except Exception:
                                patterns = None
                            if patterns:
                                st_value = patterns.ioc_match(con, bogon_ip=True)
                                if len(st_value) > 0:
                                    for ty, val in st_value.iteritems():
                                        if val == "":
                                            asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                            self.log.debug("TAG: {}, {}".format(ty, asc_asc))
                                            # subres.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                        else:
                                            ulis = list(set(val))
                                            for v in ulis:
                                                self.log.debug("TAG: {}, {}".format(ty, v))
                        else:
                            self.log.debug("Content over 500 bytes, see extracted files: {}".format(keyw))
                            carvf = path.join(self.working_dir, "carved_content_obj_{0}_{1}_{2}".format(
                                k, keyw, carved_obj_idx))
                            with open(carvf, 'wb') as f:
                                f.write(con)
                            self.log.debug(carvf, "Extracted content from object {}: {}".format(k, carvf))
                            carved_obj_idx += 1

        ###############################
        # ELEMENTS                    #
        ###############################
        # NOTE: Do not show for objstms
        if get_malform:
            options = {"verbose": True, "nocanonicalizedoutput": True, "get_malform": get_malform}
            try:
                pdfparser_result, errors = self.get_pdfparser(file_path, working_dir, options)
            except Exception as e:
                pdfparser_result = None
                self.log.debug(e)

            embed_extracted = set()
            if pdfparser_result:
                if len(pdfparser_result) == 0:
                    self.log.debug("No structure information generated for file. Please see errors.")
                else:
                    # PDF Parser will write any malformed content over 100 bytes to a file
                    files = pdfparser_result.get("files", None)
                    if files:
                        for f, l in files.iteritems():
                            if f == 'malformed':
                                for i in l:
                                    self.log.debug("Extracted malformed content in PDF Parser Analysis: {}".format(i))

                    parts = pdfparser_result.get("parts", None)
                    # Extract any embedded files
                    if parts:
                        self.log.debug("PDF Elements")
                        idx = 0
                        for p in sorted(parts):
                            self.log.debug(" * {}".format(p))
                            if "Type: /EmbeddedFile" in p and (idx <= self.max_extract):
                                getobj = p.split("\n", 1)[0].split(" ")[1]
                                if getobj in embed_extracted:
                                    continue
                                if getobj in jbig_objs:
                                    options = {
                                        "object": getobj,
                                        "dump": "embedded_file_obj_{0}".format(getobj),
                                    }
                                else:
                                    options = {
                                        "filter": True,
                                        "object": getobj,
                                        "dump": "embedded_file_obj_{0}".format(getobj),
                                    }
                                try:
                                    pdfparser_subresult, err = self.get_pdfparser(file_path, working_dir, options)
                                except Exception as e:
                                    pdfparser_subresult = None
                                    err = []
                                    self.log.debug(e)

                                if pdfparser_subresult:
                                    files = pdfparser_subresult.get("files", None)
                                    if files:
                                        self.log.debug('TAG: FILE_STRING => EmbeddedFile')
                                        embed_extracted.add(getobj)
                                        for f, l in files.iteritems():
                                            if f == 'embedded':
                                                for i in l:
                                                    self.log.debug("Extracted embedded file from obj {} "
                                                                   "in PDF Parser Analysis: {}".format(getobj, i))
                                    for e in err:
                                        self.all_errors.add(e)

                                    idx += 1

                for e in errors:
                    self.all_errors.add(e)

            #####################################################
            # Extract objects collected from above analysis     #
            #####################################################
            obj_to_extract = obj_extract_triage - embed_extracted
            for o in obj_to_extract:
                # Final check to ensure object has a stream, if not drop it.
                options = {"object": o}
                try:
                    pdfparser_result, errors = self.get_pdfparser(file_path, working_dir, options)
                except Exception as e:
                    pdfparser_result = None
                    self.log.debug(e)
                if pdfparser_result:
                    if not pdfparser_result['parts'][0].split("\n", 4)[3] == "Contains stream":
                        continue
                else:
                    continue

                if o in jbig_objs:
                    options = {
                        "object": o,
                        "dump": "extracted_obj_{}".format(o),
                    }
                else:
                    options = {
                        "filter": True,
                        "object": o,
                        "dump": "extracted_obj_{}".format(o),
                    }
                try:
                    pdfparser_result, errors = self.get_pdfparser(file_path, working_dir, options)
                except Exception as e:
                    pdfparser_result = None
                    self.log.debug(e)

                if pdfparser_result:
                    files = pdfparser_result.get("files", None)
                    if files:
                        for f, l in files.iteritems():
                            if f == 'embedded':
                                for i in l:
                                    self.log.debug("Object {} extracted in PDF Parser Analysis: {}".format(o, i))

                    for e in errors:
                        self.all_errors.add(e)

        return objstms

    def run(self):
        """Run pdf-parser.py to extract objects

        :return: dict: list of extracted files and their sha512 hash
        """
        pparser = {'heuristics': {}, 'object_streams': {}, 'errors': {}}

        contains_objstms = self.analyze(self.file_path, self.working_dir)

        #  ObjStms: Treat all ObjStms like a standalone PDF document
        if contains_objstms:
            objstm_files = self.analyze_objstm(self.file_path, self.working_dir)

            for osf in objstm_files:
                self.analyze(osf, self.working_dir, get_malform=False)

        if len(self.all_errors) > 0:
            self.log.debug("Errors Analyzing PDF")
            for e in self.all_errors:
                self.log.debug("[ERROR]: {}".format(e))

        return pparser
