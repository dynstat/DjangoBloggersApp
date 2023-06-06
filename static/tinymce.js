tinymce.init({
  selector: "textarea", //#textarea,#divarea
  auto_focus: "textarea",
  plugins:
    "wordcount code lists advlist anchor autolink autosave charmap codesample textcolor colorpicker contextmenu fullpage fullscreen help hr image insertdatetime link media noneditable pagebreak paste preview print save searchreplace tabfocus table template textpattern toc visualblocks visualchars",
  //TODO see full page defaults https://www.tinymce.com/docs/plugins/fullpage/
  //TODO look at importcss plugin and content_css https://www.tinymce.com/docs/plugins/importcss/
  // See available date formats https://www.tinymce.com/docs/plugins/insertdatetime/
  // TODO see media options https://www.tinymce.com/docs/plugins/media/
  branding: false, //adds tinymce name to bottom
  height: 500,
  max_height: 800,
  min_height: 200,
  min_width: 100,
  max_width: 900,
  insert_button_items: "",
  // menubar: 'file edit view insert format table help',
  // menu: {
  //   file: {title: 'Files', items: 'newdocument'},
  //   edit: {title: 'Edit', items: 'undo redo | cut copy paste pastetext | selectall'},
  //   insert: {title: 'Insert', items: 'link media | template hr'},
  //   view: {title: 'View', items: 'visualaid'},
  //   format: {title: 'Format', items: 'bold italic underline strikethrough superscript subscript | formats | removeformat'},
  //   tools: {title: 'Tools', items: 'spellchecker code'},
  //   access: {title: 'Accessibility', items: ''}
  // },
  // mobile: {
  //   theme: "mobile",
  //   plugsins: [""],
  //   toolbar: [""]
  // },
  preview_styles: true, //shows how formats and headings look in the menu
  // resize: 'both',
  statusbar: true,
  toolbar:
    "insert | undo redo | formatselect | bold italic backcolor | alignleft aligncenter alignright | bullist numlist | outdent indent | link image code",
  toolbar1:
    "save insert | undo redo | formatselect | bold italic backcolor | alignleft aligncenter alignright | bullist numlist | outdent indent | link image code",
  // toolbar1: 'formatselect | bold italic strikethrough forecolor backcolor | link | alignleft aligncenter alignright alignjustify  | numlist bullist outdent indent  | removeformat',
  // inline_boundaries_selector: 'a[href],code,b,i,strong,em', //don't know what this does
  visual: true, //don't know what this does
  browser_spellcheck: true,
  custom_undo_redo_levels: 20, // saves this many undo points
  //advlist_bullet_styles: "square",  // only include square bullets in list
  //advlist_number_styles: "lower-alpha",  // only include lower alpha in list
  //autosave_ask_before_unload: true, //does this work TODO
  //autosave_restore_when_empty: true,
  //autosave_interval: "5s",
  //autosave_retention: "30m",
  // charmap: [[0x2615, 'morning coffee']  ], //this overrides the char map
  // charmap_append: [    [0x2600, 'sun'],    [0x2601, 'cloud']  ], //this appends to the current char map
  // contextmenu: "copy paste link image inserttable | cell row column deletetable",
  image_caption: true,
  image_list: [
    {
      title: "Turtle Image",
      value:
        "http://www.tehcute.com/pics/201109/baby-turtle-eats-strawberry-big.jpg"
    },
    {
      title: "Dog Image",
      value: "https://www.what-dog.net/Images/faces2/scroll0015.jpg"
    }
  ],
  image_advtab: true,
  image_class_list: [
    { title: "None", value: "" },
    { title: "Responsive", value: "img-fluid" },
    { title: "Thumbnail", value: "img-thumbnail" },
    { title: "Float Left", value: "rounded float-left" },
    { title: "Float Right", value: "rounded float-right" }
  ], //TODO add image classes
  image_dimensions: true,
  // image_title: true,
  // image_prepend_url: "https://www.tinymce.com/images/",
  content_css:
    "https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0/css/bootstrap.css", //adds bootstrap or external css
  insertdatetime_dateformat: "%YYYY-%m-%d",
  insertdatetime_formats: ["%H:%M:%S", "%Y-%m-%d", "%I:%M:%S %p", "%D"],
  default_link_target: "_blank", //default links to new window
  link_context_toolbar: true,
  // link_assume_external_targets: true //TODO see  https://www.tinymce.com/docs/plugins/link/
  link_class_list: [
    { title: "None", value: "" },
    { title: "Badge Primary", value: "badge badge-primary" },
    { title: "Badge Secondary", value: "cat" }
  ], //this would be great to select a font awesome icon css
  link_list: [
    { title: "A Link preset", value: "https://www.tinymce.com" },
    { title: "Preset 2", value: "https://www.ephox.com" }
  ], //link list to common places
  // noneditable_editable_class: "mceEditable",
  noneditable_noneditable_class: "mceNonEditable",
  pagebreak_separator:
    '<div style="page-break-after: always;" class="pagebreak"></div><!-- my page break -->',
  paste_data_images: true, //allow images to be pasted
  paste_as_text: false, //updates default in menu
  paste_enable_default_filters: true,
  paste_preprocess: function (plugin, args) {
    console.log(args.content);
    // args.content += ' preprocess';
  },
  // paste_postprocess: function(plugin, args) {
  // console.log(args.node);
  // args.node.setAttribute('id', '42');
  // },
  // paste_word_valid_elements: "h3",
  paste_webkit_styles: "none", //which span styles to keep
  paste_retain_style_properties: "none", //which inline styles to keep
  paste_merge_formats: true, //merges multiple text formats like <b>
  paste_convert_word_fake_lists: true,
  plugin_preview_height: 500,
  plugin_preview_width: 650,
  save_enablewhendirty: true,
  //tabfocus_elements: ":prev,:next", //next form field
  save_onsavecallback: function () {
    console.log("Saved");
  },
  table_appearance_options: true, //removes spacing padding, border caption options
  table_grid: true, //the draggable table matrix to create table
  table_default_attributes: {
    // border: '1'
  }, //default attritbutes
  table_default_styles: {
    'border-collapsed': 'collapse', 'width': '100%'
  },
  table_responsive_width: true, //uses percentages for table size
  table_class_list: [
    { title: "None", value: "" },
    { title: "Table", value: "table" },
    { title: "Bordered Table", value: "table table-bordered" },
    { title: "Small Table", value: "table table-sm" },
    { title: "Striped", value: "table table-striped" },
    { title: "Striped Dark", value: "table table-striped table-dark" },
    { title: "Hover Rows", value: "table table-hover" }
  ],
  inline_styles: false,
  invalid_styles: 'width, height',
  table_cell_class_list: [
    { title: "None", value: "" },
    { title: "Primary", value: "table-primary" },
    { title: "Active", value: "table-active" },
    { title: "Dark", value: "table-dark" }
  ],
  table_row_class_list: [
    { title: "None", value: "" },
    { title: "Primary", value: "table-primary" },
    { title: "Active", value: "table-active" },
    { title: "Dark", value: "table-dark" }
  ],
  table_advtab: false, //disabled advanced table tab
  table_cell_advtab: false, //disable advanced cell tab
  table_row_advtab: false, //disable advanced row tab
  templates: [
    { title: "Sample Template 1", content: "<h4>sample html code</h4>" },
    { title: "Templat2 2", content: "Number 2 template stuff" }
  ],
  // textcolor_cols: "10",
  // textcolor_rows: "10",
  // textcolor_map: [
  //   "000000", "Black",
  //   "993300", "Burnt orange",
  //   "333300", "Dark olive",
  //   "003300", "Dark green",
  //   "003366", "Dark azure",
  //   "000080", "Navy Blue",
  //   "333399", "Indigo",
  //   "333333", "Very dark gray",
  //   "800000", "Maroon",
  //   "FF6600", "Orange",
  //   "808000", "Olive",
  //   "008000", "Green",
  //   "008080", "Teal",
  //   "0000FF", "Blue",
  //   "666699", "Grayish blue",
  //   "808080", "Gray",
  //   "FF0000", "Red",
  //   "FF9900", "Amber",
  //   "99CC00", "Yellow green",
  //   "339966", "Sea green",
  //   "33CCCC", "Turquoise",
  //   "3366FF", "Royal blue",
  //   "800080", "Purple",
  //   "999999", "Medium gray",
  //   "FF00FF", "Magenta",
  //   "FFCC00", "Gold",
  //   "FFFF00", "Yellow",
  //   "00FF00", "Lime",
  //   "00FFFF", "Aqua",
  //   "00CCFF", "Sky blue",
  //   "993366", "Red violet",
  //   "FFFFFF", "White",
  //   "FF99CC", "Pink",
  //   "FFCC99", "Peach",
  //   "FFFF99", "Light yellow",
  //   "CCFFCC", "Pale green",
  //   "CCFFFF", "Pale cyan",
  //   "99CCFF", "Light sky blue",
  //   "CC99FF", "Plum"
  // ],
  textpattern_patterns: [
    { start: "*", end: "*", format: "italic" },
    { start: "**", end: "**", format: "bold" },
    { start: "#", format: "h1" },
    { start: "##", format: "h2" },
    { start: "###", format: "h3" },
    { start: "####", format: "h4" },
    { start: "#####", format: "h5" },
    { start: "######", format: "h6" },
    { start: "1. ", cmd: "InsertOrderedList" },
    { start: "* ", cmd: "InsertUnorderedList" },
    { start: "- ", cmd: "InsertUnorderedList" }
  ],
  toc_depth: 3, // depth of table of contents
  toc_header: "h2", // case doesn't matter
  // toc_class: "our-toc",

  visualblocks_default_state: false,
  setup: function (editor) {
    editor.on("click", function (e) {
      // console.log("editor was clicked");
    });
  }
});

//      tinymce.init({
//             selector: '#editor',
//             inline: true,
//             height: 500,
//             menubar: false,
//             browser_spellcheck: true,
//             theme: 'modern',
//             advlist_bullet_styles: "default",
//             advlist_number_styles: "default lower-alpha upper-alpha upper-roman lower-roman",
//             plugins: [
//               'advlist autolink lists link charmap print preview pagebreak',
//               'searchreplace wordcount visualblocks visualchars code fullscreen',
//               'insertdatetime media nonbreaking save table directionality',
//               'template paste textpattern codesample'
//             ],
//             paste_retain_style_properties: "none",
//             paste_word_valid_elements: "b,strong,i,em,h1,h2,h3,h4,h5,p,ol,ul,li",
//             invalid_elements: 'style',
//             keep_styles: false,
//             // paste_as_text: true,
//             toolbar1: 'savesyllabus | undo redo copy paste | styleselect visualblocks | table',
//             toolbar2: 'formatselect | bold italic underline | bullist numlist  | link charmap | template code ',
//             save_enablewhendirty: true,
//             templates: [
//               { title: '15 weeks list', content: '<ol><li>A systematic and orderly list of activities and/or events that will comprise the total allotted time for the course. The activities, whether based on units or topics, should correspond to the number of weeks of instruction. The 15th week is the final exam period.<li><li><li><li><li><li><li><li><li><li><li><li><li><li>Final Exam Week</ol>' },
//               { title: '15 weeks with chapters', content: '<ol><li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Chapter<li>Final Exam Week</ol>' }
//             ],
//             textpattern_patterns: [
//               { start: '#', format: 'h1' },
//               { start: '##', format: 'h2' },
//               { start: '###', format: 'h3' },
//               { start: '####', format: 'h4' },
//               { start: '#####', format: 'h5' },
//               { start: '######', format: 'h6' },
//               { start: '1. ', cmd: 'InsertOrderedList' },
//               { start: '- ', cmd: 'InsertUnorderedList' }
//             ],
//             setup: function (editor) {
//               editor.addButton('savesyllabus', {
//                 text: 'Save Syllabus',
//                 onclick: function () {
//                   savetodb();
//                 }
//               });
//             }

//           });