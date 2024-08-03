from flask import Flask, render_template, request
import subprocess
import os

app = Flask(__name__)

def analyze_file(filepath):
    try:
        # Run oleid.py
        oleid_cmd = ["python", "scripts/oleid.py", filepath]
        oleid_result = subprocess.check_output(oleid_cmd, stderr=subprocess.STDOUT).decode('utf-8')

        # Clean and format oleid result
        oleid_result = oleid_result.replace("oleid 0.60.1 - http://decalage.info/oletools", "Malicious Keywords Results")
        oleid_result = oleid_result.replace("THIS IS WORK IN PROGRESS - Check updates regularly!", "")
        oleid_result = oleid_result.replace("Please report any issue at https://github.com/decalage2/oletools/issues", "")
        oleid_result = oleid_result.replace("Encoding for stdout is only cp1252, will auto-encode text with utf8 before output", "")
        oleid_result = oleid_result.replace("Filename:", "")

        # Run olevba.py
        olevba_cmd = ["python", "scripts/olevba.py", filepath]
        olevba_result = subprocess.check_output(olevba_cmd, stderr=subprocess.STDOUT).decode('utf-8')

        # Clean and format olevba result
        olevba_result = olevba_result.replace("Encoding for stdout is only cp1252, will auto-encode text with utf8 before output", "")
        olevba_result = olevba_result.replace("olevba 0.60.2 on Python 3.12.4 - http://decalage.info/python/oletools", "Malicious Macro Results")
        olevba_result = olevba_result.replace("FILE: ./uploads/sample.doc", "")
        
        return {
            "oleid_result": oleid_result.strip(),
            "olevba_result": olevba_result.strip()
        }
    except subprocess.CalledProcessError as e:
        return {"error": f"An error occurred: {e.output.decode('utf-8')}"}

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        file = request.files["file"]
        if file:
            filepath = f"./uploads/{file.filename}"
            file.save(filepath)
            result = analyze_file(filepath)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
