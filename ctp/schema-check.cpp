    //
    // schema-check.cpp -- test XML document against schema
    //
    // Published with DCI-CTP v1.1, Copyright 2007,2009, Digital Cinema Initiatives, LLC
    //
    // This program requires the Xerces-c XML library. To build:
    // $ c++ -o schema-check schema-check.cpp -lxerces-c
    //
    #include <iostream>
    #include <list>
    #include <string>
    #include  <xercesc/util/OutOfMemoryException.hpp>
    #include  <xercesc/dom/DOM.hpp>
    #include  <xercesc/parsers/XercesDOMParser.hpp>
    #include  <xercesc/framework/XMLGrammarDescription.hpp>
    #include  <xercesc/sax/ErrorHandler.hpp>
    #include  <xercesc/sax/SAXParseException.hpp>
    using std::cerr;
    using std::endl;
    XERCES_CPP_NAMESPACE_USE
    // ---------------------------------------------------------------------------
    // Utility code adapted from the DOMPrint program distributed with Xerces-c
    // simple transcoding wrapper
    class StrX
    {
       char*   fLocalForm;
    public :
       StrX(const XMLCh* const toTranscode) { fLocalForm = XMLString::transcode(toTranscode); }
       ~StrX() { XMLString::release(&fLocalForm); }
       const char* localForm() const { return fLocalForm; }
    };
    std::ostream&

operator<<(std::ostream& target, const StrX& toDump)
{
   target << toDump.localForm();
   return target;
}
// error handler interface
class DOMTreeErrorReporter : public ErrorHandler
{
public:
   void warning(const SAXParseException& toCatch) {}
   void resetErrors() {}
   void error(const SAXParseException& toCatch) {
     cerr << "Error at file \"" << StrX(toCatch.getSystemId())
           << "\", line " << toCatch.getLineNumber()
           << ", column " << toCatch.getColumnNumber() << endl
           << "   Message: " << StrX(toCatch.getMessage()) << endl;
   }
   void fatalError(const SAXParseException& toCatch) {
     cerr << "Fatal Error at file \"" << StrX(toCatch.getSystemId())
           << "\", line " << toCatch.getLineNumber()
           << ", column " << toCatch.getColumnNumber() << endl
           << "   Message: " << StrX(toCatch.getMessage()) << endl;
   }
};
// ---------------------------------------------------------------------------
int
main(int argc, const char** argv)
{
   try
     {
       XMLPlatformUtils::Initialize();
     }
   catch(const XMLException& e)
     {
       StrX tmp_e(e.getMessage());
       cerr << "Xerces initialization error: " << tmp_e.localForm() << endl;
       return 2;
     }
   // check command line for arguments
   if ( argc < 1 )
     {
       cerr << "usage: schema-check <xml-file> [<schema-file> ...]" << endl;
       return 3;
     }
   XercesDOMParser *parser = new XercesDOMParser;
   DOMTreeErrorReporter *errReporter = new DOMTreeErrorReporter();
   parser->setErrorHandler(errReporter);
   parser->setDoNamespaces(true);
   parser->setCreateEntityReferenceNodes(true);
   parser->useCachedGrammarInParse(true);
   if ( argc > 2 )
     {
       parser->setDoSchema(true);
       parser->setDoValidation(true);
       parser->setValidationSchemaFullChecking(true);
       for ( int i = 2; i < argc; i++ )
         {

           if ( parser->loadGrammar(argv[i], Grammar::SchemaGrammarType, true) == 0 )
             {
               cerr << "Error loading grammar " << std::string(argv[i]) << endl;
               return 4;
             }
         }
     }
   bool errorsOccured = true;
   try
     {
       parser->parse(argv[1]);
       errorsOccured = false;
     }
   catch ( const OutOfMemoryException& )
     {
       cerr << "Out of memory exception." << endl;
     }
   catch ( const XMLException& e )
     {
       cerr << "An error occurred during parsing" << endl
            << "    Message: " << StrX(e.getMessage()) << endl;
     }
   catch ( const DOMException& e )
     {
       const unsigned int maxChars = 2047;
       XMLCh errText[maxChars + 1];
       cerr << endl
            << "DOM Error during parsing: '" << std::string(argv[1]) << "'" << endl
            << "DOM Exception code is: " << e.code << endl;
       if ( DOMImplementation::loadDOMExceptionMsg(e.code, errText, maxChars) )
         cerr << "Message is: " << StrX(errText) << endl;
     }
   catch (...)
     {
       cerr << "An error occurred during parsing." << endl;
     }
   return errorsOccured ? 1 : 0;
}
//
// end schema-check.cpp
//

