import os

doc_id = 0
docx_id = 0

for root, dirs, files in os.walk('.'):
    for fname in files:
        if fname == 'cope.py':
            continue
        if fname[-1:] == 'x':
            os.rename(fname, "docx_{}".format(docx_id))
            docx_id += 1
        else:
            os.rename(fname, "doc_{}".format(doc_id))
            doc_id += 1