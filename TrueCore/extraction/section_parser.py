"""
TrueCore Section Parser

Splits a document into logical sections based on
known form keyword anchors.
"""

from detection.form_detector import FORM_DEFINITIONS


# -------------------------------------------------
# SECTION SPLITTING
# -------------------------------------------------

def split_sections(text):

    sections = {}

    if not text:
        return sections

    text_upper = text.upper()

    positions = []

    # -------------------------------------------------
    # FIND KEYWORD POSITIONS
    # -------------------------------------------------

    for form_name, keywords in FORM_DEFINITIONS.items():

        for keyword in keywords:

            keyword_upper = keyword.upper()
            start_index = 0

            while True:

                index = text_upper.find(keyword_upper, start_index)

                if index == -1:
                    break

                positions.append((index, form_name))

                start_index = index + len(keyword_upper)

    # -------------------------------------------------
    # SORT POSITIONS
    # -------------------------------------------------

    positions.sort()

    # -------------------------------------------------
    # EXTRACT SECTIONS
    # -------------------------------------------------

    for i, (start_pos, form_name) in enumerate(positions):

        if i + 1 < len(positions):
            end_pos = positions[i + 1][0]
        else:
            end_pos = len(text)

        section_text = text[start_pos:end_pos]

        # Append instead of overwrite
        if form_name not in sections:
            sections[form_name] = section_text
        else:
            sections[form_name] += "\n\n" + section_text

    # -------------------------------------------------
    # CLINICAL SECTION DETECTION
    # -------------------------------------------------

    CLINICAL_SECTION_KEYWORDS = {
        "diagnosis_section": ["DIAGNOSIS", "ASSESSMENT"],
        "procedure_section": ["PROCEDURE", "TREATMENT"],
        "imaging_section": ["MRI", "CT", "X-RAY", "ULTRASOUND"],
        "provider_section": ["PROVIDER", "PHYSICIAN", "SIGNED BY"],
        "authorization_section": ["AUTHORIZATION", "AUTH#", "AUTH NUMBER"],
    }

    for section_name, keywords in CLINICAL_SECTION_KEYWORDS.items():


        for keyword in keywords:

            keyword_upper = keyword.upper()
            index = text_upper.find(keyword_upper)

            if index != -1:

                end = min(index + 800, len(text))
                sections[section_name] = text[index:end]
                break

    return sections