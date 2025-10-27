# -*- coding: utf-8 -*-
"""
Created on Mon Jul  1 09:04:19 2024

@author: Evgeny Kolonsky
"""
#VERSION = 'v0.3.1' # 7z archives functionality added
#VERSION = 'v0.5.2' # image comparison
VERSION = 'v0.5.3' # cos_distance replaced by similarity_ratio
VERSION = 'v0.6.0' # image compared by perceptual hash + icon of similar image
VERSION = 'v0.6.1' # automatic threshold + shared config

import warnings
warnings.filterwarnings('ignore', category=FutureWarning)


import os, shutil
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
#from hebrew_tokenizer.tokenizer import tokenizer
import pymupdf 
import codecs
import datetime
import zipfile, py7zr
from xml.sax.saxutils import escape
from time import mktime
import difflib
import numpy as np
#import pyexcel_xls
#
from highlight import highlight_pdf, extract_text_from_pdf, \
                extract_images_from_pdf, hashes_compare
                


print(f'Sumbissions similarity check {VERSION}')
print('Evgeny Kolonsky, Technion Physics, 2024 - 2025 \n')


from config import source_folder, work_folder, report_folder
from config import THRESHOLD_PERCENTILE, MIN_DAYS_DISTANCE, ALLOWED_IMAGES_COPIED
from config import HASH_DISTANCE_THRESHOLD, MIN_PIXEL_SIZE, NGRAM_MIN, NGRAM_MAX

            
print('Parameters read.')


#%% Unpacking

def unpack_inplace(zippedFile):
    
    path = os.path.dirname(zippedFile)
    
    with zipfile.ZipFile(zippedFile, 'r') as zfile:

        for zi in zfile.infolist():
            
            extractedfile = zfile.extract(zi,path=path)
            
            # preserve creation time
            date_time = mktime(zi.date_time + (0, 0, -1))
            os.utime(extractedfile, (date_time, date_time))
            #print(extractedfile)
            if extractedfile.endswith('.zip'):
                unpack_inplace(extractedfile)
            elif extractedfile.endswith('.7z'):
                with py7zr.SevenZipFile( extractedfile, "r") as archive:
                    archive.extractall(os.path.dirname(extractedfile))    
                
    os.remove(zippedFile)
    return
        

def copy_unpack(archive, source_folder, work_folder):
    
    semester_id = archive.split('_')[0]  # 2023.01_rmp.zip
    destination_folder = f'{work_folder}/{semester_id}'
    
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)
        
    shutil.copy2(f'{source_folder}/{archive}', f'{destination_folder}/{archive}')
    unpack_inplace(f'{destination_folder}/{archive}')
    return


# clean up work folder
print('Cleaning work folder..')
if os.path.exists(work_folder):
    shutil.rmtree(work_folder)
os.makedirs(work_folder)

print('Unpacking..')
archives = [file for file in os.listdir(source_folder) if file.endswith('.zip')]
for archive in sorted(archives):
    if archive.endswith('.zip'):
        print(archive)
        copy_unpack(archive, source_folder, work_folder)
        
# last archive in sorted list is the semester to be checked
semester_to_check = archive.split('_')[0]
print(f'Unpacking done. Semester to be checked: {semester_to_check}')



#%% Building model

    
def get_content(filename):
    extension = filename.split('.')[-1]
    images = {}
    if extension == 'pdf':
        doc = pymupdf.open(filename)
        text = extract_text_from_pdf(doc)
        images = extract_images_from_pdf(doc)
        doc.close()
    elif extension in ['csv', 'txt', 'tsv']:
        try: 
            with open(filename, 'r') as f:
                text = f.read()
        except Exception as err:
            print(f'Exception {err} while reading file {filename}. Continued.')
            text = ''
    else:
        text = ''
        
    return text, images
    
def get_attributes(file_path):
    
    dirlevels = file_path.replace(work_folder,'').replace('\\', '/').split('/')
    
    # debug
    x = [d for d in dirlevels if 'assignsubmission_file' in d]
    if len(x) == 0:
        #print(file_path)
        moodle_name = ['student_undefined', 'id_undefined']
    # end debug
    else:
        moodle_name = [d for d in dirlevels if 'assignsubmission_file' in d][0].split('_')
        
    semester_id = dirlevels[1] # YYYY.NN
    filename = dirlevels[-1]
    student_name = moodle_name[0]
    submission_id = moodle_name[1]
    submission_time = os.path.getmtime(file_path)
    
    txt, images = get_content(file_path)
    #txt = preprocess(txt) # kes 
    txt_size = len(txt.split())
    
    result = {}
    result['semester_id'] = semester_id
    result['submission_id'] = submission_id
    result['student_name'] = student_name
    result['timestamp'] = submission_time
    result['file_path'] = [file_path]
    result['filename'] = [filename]
    result['txt'] = txt
    result['chain'] = txt.split()
    result['size_words'] = txt_size
    result['images'] = images
    return result

def build():
    attributes = {}
    for dirpath, dirnames, filenames in os.walk(work_folder):
        for filename in filenames:
            file_path = f'{dirpath}/{filename}'
            attr = get_attributes(file_path)
            
            submission_id = attr['submission_id']
            
            if submission_id not in attributes.keys():
                # submission encountered for the first time
                attributes[submission_id] = attr
            else:
                # new file in existing submission
                # leave the lates timestamp
                tsnew = attr['timestamp']
                tsold = attributes[submission_id]['timestamp']
                if tsnew > tsold:
                    attributes[submission_id]['timestamp'] = tsnew
                # list concat
                attributes[submission_id]['filename'] += attr['filename']
                attributes[submission_id]['file_path'] += attr['file_path'] 
                # add text and size
                attributes[submission_id]['txt'] += '\n' +attr['txt']
                attributes[submission_id]['chain'] += attr['chain']
                attributes[submission_id]['images'] = attr['images'] # suggested here that submission has only one file
                attributes[submission_id]['size_words'] += attr['size_words']
            
            print('.', end='')
    print('Processed ', len(attributes))
    return attributes



print('Building text corpus ..')
attributes = build()   
print('Text corpus collection complete.')   

print('Fitting model..')

vectorizer = TfidfVectorizer(ngram_range=(NGRAM_MIN,NGRAM_MAX))

texts = [attributes[sid]["txt"] for sid in attributes.keys()]
  
tfidf = vectorizer.fit_transform(texts)
print('Caluclating cos distance')
similarity_cos = cosine_similarity(tfidf)
N = similarity_cos.shape[0]


            

print('Fitting done.')

#%%
print('Evaluating data..')

distances = []

for i, keyi in enumerate(attributes.keys()):

    attr_i = attributes[keyi]
    # check only last semester
    # comment to check all semesters
    if attr_i["semester_id"] != semester_to_check:
        continue
    
    dist_i = 0
    for j, keyj in enumerate(attributes.keys()):
        attr_j = attributes[keyj]
        ts1, ts2 = attr_i["timestamp"], attr_j["timestamp"]
        days_distance = (ts1 - ts2) / 60 /60 /24
        if days_distance <= MIN_DAYS_DISTANCE:
            continue
        
        if similarity_cos[i,j] > dist_i:
            dist_i = similarity_cos[i,j]
    distances.append(dist_i)
    
THRESHOLD = np.percentile(distances, THRESHOLD_PERCENTILE)
print(f'THRESHOLD set automatically {THRESHOLD:0.2f}')
        







#%% Reporting result
print('Building report...')

def copy_to_report(attr, return_url_type='excel'):

    submission_id = attr['submission_id']
    student_name = attr['student_name']
    
    #relative_folder = f'{submission_id}_{student_name}'.replace(' ', '_')
    relative_folder = f'{submission_id}'
    destination_folder = f'{report_folder}/{relative_folder}'
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)
    
    new_file_path = [shutil.copy(file_path, destination_folder) for file_path in attr['file_path'] ]
    
    #

    link = f'./{relative_folder}'
    shortname = submission_id
        
    if return_url_type == 'excel':
        # excel-ready version
        url = f'=HYPERLINK("{link}","{shortname}")'
    else: # html type
        url = f'"file://{link}"'
    return url, new_file_path


#%% Excel report helper


def _column_letter(idx):

    letters = ''
    while idx:
        idx, remainder = divmod(idx - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def build_excel_sheet(rows):

    sheet_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
        '<sheetData>'
    ]

    for row_idx, row in enumerate(rows, start=1):
        sheet_lines.append(f'<row r="{row_idx}">')
        for col_idx, cell in enumerate(row, start=1):
            cell_ref = f'{_column_letter(col_idx)}{row_idx}'
            value = escape(str(cell))
            sheet_lines.append(
                f'<c r="{cell_ref}" t="inlineStr"><is><t>{value}</t></is></c>'
            )
        sheet_lines.append('</row>')

    sheet_lines.extend(['</sheetData>', '</worksheet>'])
    return '\n'.join(sheet_lines)


def write_excel_report(report_text, destination_folder):

    rows = []
    for line in report_text.replace('\r\n', '\n').split('\n'):
        rows.append(line.split('\t'))

    sheet_xml = build_excel_sheet(rows)

    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
        '  <sheets>\n'
        '    <sheet name="Report" sheetId="1" r:id="rId1"/>\n'
        '  </sheets>\n'
        '</workbook>'
    )

    workbook_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        '  <Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>\n'
        '  <Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>\n'
        '</Relationships>'
    )

    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
        '  <fonts count="1">\n'
        '    <font>\n'
        '      <sz val="11"/>\n'
        '      <color theme="1"/>\n'
        '      <name val="Calibri"/>\n'
        '      <family val="2"/>\n'
        '    </font>\n'
        '  </fonts>\n'
        '  <fills count="1">\n'
        '    <fill>\n'
        '      <patternFill patternType="none"/>\n'
        '    </fill>\n'
        '  </fills>\n'
        '  <borders count="1">\n'
        '    <border/>\n'
        '  </borders>\n'
        '  <cellStyleXfs count="1">\n'
        '    <xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>\n'
        '  </cellStyleXfs>\n'
        '  <cellXfs count="1">\n'
        '    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>\n'
        '  </cellXfs>\n'
        '  <cellStyles count="1">\n'
        '    <cellStyle name="Normal" xfId="0" builtinId="0"/>\n'
        '  </cellStyles>\n'
        '</styleSheet>'
    )

    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
        '  <Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
        '  <Default Extension="xml" ContentType="application/xml"/>\n'
        '  <Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>\n'
        '  <Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\n'
        '  <Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>\n'
        '</Types>'
    )

    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        '  <Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>\n'
        '</Relationships>'
    )

    excel_path = os.path.join(destination_folder, 'report.xlsx')

    with zipfile.ZipFile(excel_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', content_types_xml)
        zf.writestr('_rels/.rels', root_rels_xml)
        zf.writestr('xl/workbook.xml', workbook_xml)
        zf.writestr('xl/_rels/workbook.xml.rels', workbook_rels_xml)
        zf.writestr('xl/styles.xml', styles_xml)
        zf.writestr('xl/worksheets/sheet1.xml', sheet_xml)


report = 'semester \t submission_id \t student_name \t when_submitted \t filename \t size_words \t num_figures\t\
          semester \t submission_id \t student_name \t when_submitted \t filename \t size_words \t num_figures \t\
          similarity_ratio \t  same_images \t days_between \n'



# clean up report folder
if os.path.exists(report_folder):
    shutil.rmtree(report_folder)
os.makedirs(report_folder)
   
reportfilename = f'{report_folder}/report.txt'




for i, keyi in enumerate(attributes.keys()):
    
    attr_i = attributes[keyi]
    # check only last semester
    # comment to check all semesters
    if attr_i["semester_id"] != semester_to_check:
        continue
    
    
    for j, keyj in enumerate(attributes.keys()):
        
        # suggestion that cos distance usually 2.5-3 times lower that similarity ratio distance
        # it will be used to accelerate report generation
        # ratio is calculated far more slowly than cos distance
        # and ratio is calulated for all pairs (i,j), i.e it takes ~N^2 time
        # so we will compare cos_distance with threshold/5
        # if it is small enough the ratio calculation will be skipped
        
        if similarity_cos[i, j] < THRESHOLD / 5:
            continue
        
        attr_j = attributes[keyj]
        
        similarity_ratio = difflib.SequenceMatcher(None, attr_i['chain'], attr_j['chain']).ratio()
        similar_images = hashes_compare(attr_i['images'], attr_j['images']) 
        images_copied = len(similar_images)
        
        #if (cos_distance < THRESHOLD) and (images_copied <= ALLOWED_IMAGES_COPIED):
        if (similarity_ratio < THRESHOLD) and (images_copied <= ALLOWED_IMAGES_COPIED):
            continue;
    

        ts1, ts2 = attr_i["timestamp"], attr_j["timestamp"]
        days_distance = (ts1 - ts2) / 60 /60 /24
        if days_distance <= MIN_DAYS_DISTANCE:
            continue
            
        dt1, dt2 = str(datetime.datetime.fromtimestamp(ts1)), \
                   str(datetime.datetime.fromtimestamp(ts2))
                   
        
        sem1, sem2   = attr_i["semester_id"],   attr_j["semester_id"]
        id1, id2     = attr_i["submission_id"], attr_j["submission_id"]
        stud1, stud2 = attr_i["student_name"],  attr_j["student_name"]
        file1, file2 = attr_i["filename"],      attr_j["filename"]
        size1, size2 = attr_i["size_words"],    attr_j["size_words"]
        

        # copy to report folder
        url1, submissionfiles1 = copy_to_report(attr_i)
        url2, submissionfiles2 = copy_to_report(attr_j)
        
        # highlight differencies for pdf
        pdfs1 = [file for file in submissionfiles1 if file.endswith('.pdf')]
        pdfs2 = [file for file in submissionfiles2 if file.endswith('.pdf')]
        if len(pdfs1) == 1 and len(pdfs2) == 1: # 1 to 1 compare available
            pdf_similar = pdfs1[0]
            pdf_source = pdfs2[0]
            
            destination_folder = f'{report_folder}/{id1}' 
            output_pdf_name = f'{id1}_{id2}.pdf'
            output_pdf_path = f'{destination_folder}/{output_pdf_name}'
            print(output_pdf_path)
            
            # debug
            highlight_pdf(pdf_similar, pdf_source, output_pdf_path)
            
        # ---
        figures1 = len(attr_i['images'])
        figures2 = len(attr_j['images'])
        report += f'{sem1}\t{url1}\t{stud1}\t{dt1}\t{file1}\t{size1}\t{figures1}\t\
                    {sem2}\t{url2}\t{stud2}\t{dt2}\t{file2}\t{size2}\t{figures2}\t\
                    {similarity_ratio:.2f}\t\
                    {images_copied:.0f}\t\
                    {days_distance:.0f} \n'

    
report += '\nGeneral:\n'
report += f'Report produced: \t{datetime.datetime.now().strftime("%Y-%m-%d %H:%M")} \n'
report += f'Application version: \t{VERSION}\n'
report += f'Source archives: \t{archives}\n\n'

ts_total = [attributes[key]['timestamp'] for key in attributes.keys() ]
ts_tocheck = [attributes[key]['timestamp'] for key in attributes.keys() 
              if attributes[key]['semester_id'] == semester_to_check]

report += f'Submissions statistics:\n'
report += f'Earliest submission date:\t {datetime.datetime.fromtimestamp(min(ts_total)).strftime("%Y-%m-%d")}\n'
report += f'Last submission date:\t {datetime.datetime.fromtimestamp(max(ts_tocheck)).strftime("%Y-%m-%d")}\n'
report += f'Total submissions:\t {len(ts_total)}\n'
report += f'This semester submissions:\t {len(ts_tocheck)} \n\n'

report += f'Parameters:\n'
report += f'THRESHOLD = {THRESHOLD:.2f}\n'
report += f'THRESHOLD_PERCENTILE = {THRESHOLD_PERCENTILE}\n'
report += f'NGRAM_MIN = {NGRAM_MIN}\n'
report += f'NGRAM_MAX = {NGRAM_MAX}\n'
report += f'MIN_DAYS_DISTANCE = {MIN_DAYS_DISTANCE}\n'
report += f'ALLOWED_IMAGES_COPIED = {ALLOWED_IMAGES_COPIED}\n'
report += f'MIN_PIXEL_SIZE = {MIN_PIXEL_SIZE}\n'
report += f'HASH_DISTANCE_THRESHOLD = {HASH_DISTANCE_THRESHOLD}\n\n'


with codecs.open(reportfilename, 'w', 'utf-8') as f:
    f.write(report)

write_excel_report(report, report_folder)

print(f'Done: see {report_folder}/report.txt')
print(f'Excel version saved as {report_folder}/report.xlsx')
print('Copy-Paste report.txt content to Excel table for interactive features.')

