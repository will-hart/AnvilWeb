/* start the editor from the textarea */
window.onload = function() {
    var cmEditor = CodeMirror.fromTextArea(document.getElementById("editor"),{
        indentUnit: 4,
        lineNumbers: true,
        theme: 'ambiance'
    }).setSize("100%", "600");
    
    // set up the editor
}