// vim: tw=100 expandtab ts=2:

/* insert some text into form */
function insert(text) {
  var textarea = document.forms[0].comment;
  if (textarea) {
    if (textarea.createTextRange && textarea.caretPos) { // IE
      var caretPos = textarea.caretPos;
      caretPos.text = caretPos.text.charAt(caretPos.text.length - 1) == ' ' ? text + ' ' : text;
    } else if (textarea.setSelectionRange) { // Firefox
      var start = textarea.selectionStart;
      var end = textarea.selectionEnd;
      textarea.value = textarea.value.substr(0, start) + text + textarea.value.substr(end);
      textarea.setSelectionRange(start + text.length, start + text.length);
    } else {
      textarea.value += text + ' ';
    }
    textarea.focus();
    return false;
  }
  return true;
}

/* set POST variable "reply" to answering message and insert >>msgid into form */
function quickreply(articlehash, parenthash_full) {
  var nt = document.getElementById('newthread');
  if (nt) {
    document.forms[0].reply.value = parenthash_full;
    nt.value = 'reply to thread'
  }
  insert('>>' + articlehash + '\n');
  if (quote != '') {
    insert('>' + quote + '\n');
  }
  return false;
}

/* highlight some message */
function highlight(articlehash) {
  /* turn off previos highlights */
	var cells = document.getElementsByTagName("div");
	for(var i=0;i<cells.length;i++) {
          if(cells[i].className == "highlight") cells[i].className = "message";
          if(cells[i].className == "highlightroot") cells[i].className = "messageroot";
        }
  /* make highlight */
  if(document.getElementById(articlehash).className == "message") document.getElementById(articlehash).className = 'highlight'; 
    else document.getElementById(articlehash).className = 'highlightroot';
  /* jump to post */
  var match = /^([^#]*)/.exec(document.location.toString()); /* extract full url without trailing #part */
  document.location = match[1] + "#" + articlehash; /* jump to #articlehash */
  return false;
}

/* get text selected by user */
function getSelectionText() {
  var text = '';
  if (window.getSelection) {
    text = window.getSelection().toString();
  } else if (document.selection && document.selection.type != 'Control') {
    text = document.selection.createRange().text;
  }
  return text;
}

/* set global variable with selected text */
function get_quote() {
  quote = getSelectionText();
  return true;
}
