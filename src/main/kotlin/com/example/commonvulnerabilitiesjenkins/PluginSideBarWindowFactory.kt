package com.example.commonvulnerabilitiesjenkins

import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import java.awt.BorderLayout
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*

class PluginSideBarWindowFactory : ToolWindowFactory {

    private val XXE_SEARCH_STRINGS = listOf(
        "DocumentBuilderFactory",
        "javax.xml.transform.TransformerFactory",
        "javax.xml.validation.Validator",
        "javax.xml.validation.SchemaFactory",
        "javax.xml.transform.sax.SAXTransformerFactory",
        "org.xml.sax.XMLReader",
        "org.dom4j.io.SAXReader",
        "org.jdom2.input.SAXBuilder",
        "javax.xml.bind.Unmarshaller"
    )

    private val XSS_SEARCH_REGEX = Regex("<script[^>]*>.*?(\\$\\{).*?</script>", RegexOption.DOT_MATCHES_ALL)
    private val XSS_SEARCH_STRINGS = listOf(
        "escape-by-default='false'",
        "escape-by-default=\"false\"",
        "<st:out",
        "<j:out",
        "javascript:",
        "data:",
        "Element.innerHTML",
        "Element.outerHTML",
        "Element.insertAdjacentHTML"
    )

    private val UNENCRYPTED_PASSWORDS_STRINGS = listOf("<f:password", "f.password")
    private val RCE_SEARCH_STRINGS = listOf(
        "groovy.lang.GroovyShell",
        "groovy.text.SimpleTemplateEngine",
        "groovy.util.GroovyScriptEngine",
        "hudson.ExpressionFactory2",
        "hudson.util.spring.BeanBuilder",
        "javaposse.jobdsl.dsl.DslScriptLoader"
    )

    private val CSRF_SEARCH_REGEX = Regex("do[A-Z][a-z]")
    private val CSRF_SEARCH_STRINGS = listOf("@WebMethod")

    private val MISSING_PERMS_SEARCH_REGEX = Regex("doFillCredentials.*Items")

    private val YAML_SEARCH_STRINGS = listOf("new Yaml(")

    private val SSL_SEARCH_STRINGS = listOf("setDefaultSSLSocketFactory", "SSLContext")

    private val GENERAL_RCE_SEARCH_STRINGS = listOf("Runtime.exec", "exec")

    private val BAD_LIBS_DEFAULTS_SEARCH_STRINGS =
        listOf("org.apache.commons.digester.Digester", "org.apache.commons.digester3.Digester")


    private val listModel: DefaultListModel<SearchResult> = DefaultListModel<SearchResult>()

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = JPanel(BorderLayout())

        findPotentialVulnerabilities(project)

        val fileList = JList(listModel)
        fileList.selectionMode = ListSelectionModel.SINGLE_SELECTION

        fileList.addMouseListener(goToLineOnDoubleClick(project, fileList))

        val scrollPane = JBScrollPane(fileList)
        panel.add(scrollPane, BorderLayout.CENTER)

        val refreshButton = JButton("Refresh")
        refreshButton.addActionListener {
            listModel.clear()
            findPotentialVulnerabilities(project)
        }

        panel.add(refreshButton, BorderLayout.SOUTH)

        val contentFactory = ContentFactory.getInstance()
        val content = contentFactory.createContent(panel, "", false)

        toolWindow.contentManager.addContent(content)
    }

    private fun findFilesWithExtension(directory: VirtualFile, extension: String): List<VirtualFile> {
        val files = mutableListOf<VirtualFile>()
        collectFilesWithExtension(directory, extension, files)
        return files
    }

    private fun collectFilesWithExtension(directory: VirtualFile, extension: String, files: MutableList<VirtualFile>) {
        for (file in directory.children) {
            if (file.isDirectory) {
                collectFilesWithExtension(file, extension, files)
            } else if (file.extension == extension) {
                files.add(file)
            }
        }
    }

    private fun findPotentialVulnerabilities(project: Project) {
        val srcDir = findSrcDirectory(project)
        if (srcDir != null) {
            val javaFiles = findFilesWithExtension(srcDir, "java")
            val jellyAndGroovyFiles =
                findFilesWithExtension(srcDir, "jelly").plus(findFilesWithExtension(srcDir, "groovy"))

            findXXE(javaFiles)
            findXSSVulnerabilities(jellyAndGroovyFiles)
            findUnencryptedPasswords(jellyAndGroovyFiles)
            findRCEVulnerabilities(javaFiles)
            findCSRFVulnerabilities(javaFiles)
            findMissingPermsVulnerabilities(javaFiles)
            findYamlVulnerabilities(javaFiles)
            findSSLVulnerabilities(javaFiles)
            findGeneralRCEVulnerabilities(javaFiles)
            findBadLibrariesVulnerabilities(javaFiles)

            if (listModel.isEmpty) {
                listModel.addElement(SearchResult(null, null, 0, null))
            }

        } else {
            listModel.addElement(SearchResult(null, null, 0, null))
        }
    }

    private fun findSrcDirectory(project: Project): VirtualFile? {
        val baseDir = project.baseDir
        return baseDir?.findChild("src")?.takeIf { it.isDirectory }
    }

    private fun findXXE(javaFiles: List<VirtualFile>) {
        fileContainAnyStringOflist(XXE_SEARCH_STRINGS, javaFiles, "XXE")
    }

    private fun fileContainAnyStringOflist(stringList: List<String>, files: List<VirtualFile>, vulnName: String) {
        files.forEach { file ->
            val content = file.contentsToByteArray().toString(Charsets.UTF_8)
            val lines = content.lines()
            var offset = 0
            lines.forEachIndexed { index, line ->
                if (stringList.any { xxe -> xxe in line }) {
                    listModel.addElement(SearchResult(file, index, offset, vulnName))
                }
                offset += line.length + 1
            }
        }
    }

    private fun fileContainsRegex(regex: Regex, files: List<VirtualFile>, vulnName: String) {
        files.forEach { file ->
            val content = file.contentsToByteArray().toString(Charsets.UTF_8)
            val regexRes = regex.findAll(content)
            for (res in regexRes.iterator()) {
                val lineNumber = content.substring(0, res.groups[0]!!.range.first).count { char -> char == '\n' }
                listModel.addElement(SearchResult(file, lineNumber, res.groups[0]!!.range.first, vulnName))
            }
        }
    }

    private fun findXSSVulnerabilities(jellyFiles: List<VirtualFile>) {
        fileContainsRegex(XSS_SEARCH_REGEX, jellyFiles, "XSS")
        fileContainAnyStringOflist(XSS_SEARCH_STRINGS, jellyFiles, "XSS")
    }

    private fun findUnencryptedPasswords(jellyFiles: List<VirtualFile>) {
        fileContainAnyStringOflist(UNENCRYPTED_PASSWORDS_STRINGS, jellyFiles, "Unencrypted Passwords")
    }

    private fun findRCEVulnerabilities(javaFiles: List<VirtualFile>) {
        fileContainAnyStringOflist(RCE_SEARCH_STRINGS, javaFiles, "RCE")
    }

    private fun findCSRFVulnerabilities(javaFiles: List<VirtualFile>) {
        fileContainsRegex(CSRF_SEARCH_REGEX, javaFiles, "CSRF")
        fileContainAnyStringOflist(CSRF_SEARCH_STRINGS, javaFiles, "CSRF")
    }

    private fun findMissingPermsVulnerabilities(javaFiles: List<VirtualFile>) {
        fileContainsRegex(MISSING_PERMS_SEARCH_REGEX, javaFiles, "Missing Perms")
    }

    private fun findYamlVulnerabilities(javaFiles: List<VirtualFile>) {
        fileContainAnyStringOflist(YAML_SEARCH_STRINGS, javaFiles, "Yaml")
    }

    private fun findSSLVulnerabilities(javaFiles: List<VirtualFile>) {
        fileContainAnyStringOflist(SSL_SEARCH_STRINGS, javaFiles, "SSL")
    }

    private fun findGeneralRCEVulnerabilities(javaFiles: List<VirtualFile>) {
        fileContainAnyStringOflist(GENERAL_RCE_SEARCH_STRINGS, javaFiles, "RCE General")
    }

    private fun findBadLibrariesVulnerabilities(javaFiles: List<VirtualFile>) {
        fileContainAnyStringOflist(BAD_LIBS_DEFAULTS_SEARCH_STRINGS, javaFiles, "Bad Libs")
    }

    private fun goToLineOnDoubleClick(project: Project, fileList: JList<SearchResult>): MouseAdapter {
        return object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) {
                    val selectedValue = fileList.selectedValue
                    if (selectedValue?.file != null && selectedValue.lineNumber != null) {
                        OpenFileDescriptor(project, selectedValue.file, selectedValue.offset).navigate(true)
                    }
                }
            }
        }
    }
}