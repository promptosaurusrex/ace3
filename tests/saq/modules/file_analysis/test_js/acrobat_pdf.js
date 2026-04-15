// Simulates a real Acrobat-extracted PDF JavaScript payload: uses only
// bracket-notation calls on PDF-specific globals like app, util, SOAP,
// getField. No whole-word JS keywords — this exercises the \w\( branch of
// the is_javascript_file() grep gate AND the harness's pre-populated
// Acrobat globals.
app["setTimeOut"](util["stringFromString"](SOAP["streamDecode"](getField("btn1")["value"], "base64")), 500);
