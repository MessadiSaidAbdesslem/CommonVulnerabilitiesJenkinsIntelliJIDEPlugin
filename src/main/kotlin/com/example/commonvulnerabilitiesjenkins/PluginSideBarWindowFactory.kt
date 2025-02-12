package com.example.commonvulnerabilitiesjenkins

import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import java.awt.BorderLayout
import java.awt.GridLayout
import java.awt.event.ActionListener
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.ListSelectionModel

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

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = JPanel()

        panel.layout = GridLayout(5, 1)

        val xxePanel = createSectionPanelXXE(project)
        panel.add(xxePanel)

        val xssPanel = createSectionPanelXSS(project)
        panel.add(xssPanel)

        val passPanel = createSectionPanelUnencryptedPasswords(project)
        panel.add(passPanel)

        val rcePanel = createSectionRCE(project)
        panel.add(rcePanel)

        val csrfPanel = createSectionCSRF(project)
        panel.add(csrfPanel)

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

    private fun findSrcDirectory(project: Project): VirtualFile? {
        val baseDir = project.baseDir
        return baseDir?.findChild("src")?.takeIf { it.isDirectory }
    }

    private fun createSectionPanelXXE(project: Project): JPanel {
        val listModel = DefaultListModel<SearchResult>()

        val sectionPanel = createGenericSection(project, "Potential XXE", listModel, {
            listModel.clear()
            val srcDir = findSrcDirectory(project)
            if (srcDir != null) {
                val files = findFilesWithExtension(srcDir, "java")

                files.forEach { file ->
                    val content = file.contentsToByteArray().toString(Charsets.UTF_8)
                    val lines = content.lines()
                    var offset = 0
                    lines.forEachIndexed { index, line ->
                        if (XXE_SEARCH_STRINGS.any { xxe -> xxe in line }) {
                            listModel.addElement(SearchResult(file, index, offset))
                        }
                        offset += line.length + 1
                    }
                }

                if (listModel.isEmpty) {
                    listModel.addElement(SearchResult(null, null, 0))
                }

            } else {
                listModel.addElement(SearchResult(null, null, 0))
            }
        })
        return sectionPanel
    }

    private fun createSectionPanelXSS(project: Project): JPanel {
        val listModel = DefaultListModel<SearchResult>()

        val sectionPanel = createGenericSection(project, "Potential XSS", listModel, {
            listModel.clear()
            val srcDir = findSrcDirectory(project)
            if (srcDir != null) {
                val files = findFilesWithExtension(srcDir, "jelly")
                files.forEach { file ->
                    // regex check for "${" between script tags
                    val content = file.contentsToByteArray().toString(Charsets.UTF_8)
                    val regexRes = XSS_SEARCH_REGEX.findAll(content)
                    for (res in regexRes.iterator()) {
                        val lineNumber = content.substring(0, res.groups[0]!!.range.first)
                            .count { char -> char == '\n' }
                        listModel.addElement(SearchResult(file, lineNumber, res.groups[0]!!.range.first))
                    }

                    // check for common vulnerable XSS inputs
                    val lines = content.lines()
                    var offset = 0
                    lines.forEachIndexed { index, line ->
                        if (XSS_SEARCH_STRINGS.any { xss -> xss in line }) {
                            listModel.addElement(SearchResult(file, index, offset))
                        }
                        offset += line.length + 1
                    }

                }
                if (listModel.isEmpty) {
                    listModel.addElement(SearchResult(null, null, 0))
                }
            } else {
                listModel.addElement(SearchResult(null, null, 0))
            }
        })
        return sectionPanel
    }

    private fun createSectionPanelUnencryptedPasswords(project: Project): JPanel {
        val listModel = DefaultListModel<SearchResult>()

        val sectionPanel = createGenericSection(project, "Potenitial Unencrypted password", listModel, {
            listModel.clear()
            val srcDir = findSrcDirectory(project)
            if (srcDir != null) {
                val jellyAndGroovyFiles =
                    findFilesWithExtension(srcDir, "jelly")
                        .plus(findFilesWithExtension(srcDir, "groovy"))


                jellyAndGroovyFiles.forEach { file ->
                    val content = file.contentsToByteArray().toString(Charsets.UTF_8)
                    val lines = content.lines()
                    var offset = 0
                    lines.forEachIndexed { index, line ->
                        if (UNENCRYPTED_PASSWORDS_STRINGS.any { passStr -> passStr in line }) {
                            listModel.addElement(SearchResult(file, index, offset))
                        }
                        offset += line.length + 1
                    }
                }

                if (listModel.isEmpty) {
                    listModel.addElement(SearchResult(null, null, 0))
                }

            } else {
                listModel.addElement(SearchResult(null, null, 0))
            }
        })
        return sectionPanel
    }

    private fun createSectionRCE(project: Project): JPanel {
        val listModel = DefaultListModel<SearchResult>()
        val sectionPanel = createGenericSection(project, "Potential RCE", listModel, {
            listModel.clear()
            val srcDir = findSrcDirectory(project)
            if (srcDir != null) {
                val files = findFilesWithExtension(srcDir, "java")

                files.forEach { file ->
                    val content = file.contentsToByteArray().toString(Charsets.UTF_8)
                    val lines = content.lines()
                    var offset = 0
                    lines.forEachIndexed { index, line ->
                        if (RCE_SEARCH_STRINGS.any { rce -> rce in line }) {
                            listModel.addElement(SearchResult(file, index, offset))
                        }
                        offset += line.length + 1
                    }
                }

                if (listModel.isEmpty) {
                    listModel.addElement(SearchResult(null, null, 0))
                }
            } else {
                listModel.addElement(SearchResult(null, null, 0))
            }
        })

        return sectionPanel
    }

    private fun createSectionCSRF(project: Project): JPanel {
        val listModel = DefaultListModel<SearchResult>()

        val sectionPanel = createGenericSection(project, "Potential CSRF", listModel, {
            listModel.clear()
            val srcDir = findSrcDirectory(project)
            if (srcDir != null) {
                val files = findFilesWithExtension(srcDir, "java")
                files.forEach { file ->
                    val contents = file.contentsToByteArray().toString(Charsets.UTF_8)
                    val regexRes = CSRF_SEARCH_REGEX.findAll(contents)
                    // looking for function names starting with do[A-Z][a-z]
                    for (res in regexRes.iterator()) {
                        val lineNumber = contents.substring(0, res.groups[0]!!.range.first).count { char ->
                            char == '\n'
                        }
                        listModel.addElement(SearchResult(file, lineNumber, res.groups[0]!!.range.first))
                    }

                    val lines = contents.lines()
                    var offset = 0
                    lines.forEachIndexed { index, line ->
                        if (CSRF_SEARCH_STRINGS.any { csrf -> csrf in line }) {
                            listModel.addElement(SearchResult(file, index, offset))
                        }
                        offset += 1 + line.length
                    }
                }
                if (listModel.isEmpty) {
                    listModel.addElement(SearchResult(null, null, 0))
                }
            } else {
                listModel.addElement(SearchResult(null, null, 0))
            }
        })

        return sectionPanel
    }

    private fun createGenericSection(
        project: Project,
        title: String,
        listModel: DefaultListModel<SearchResult>,
        refreshAction: ActionListener
    ): JPanel {
        val sectionPanel = JPanel(BorderLayout())

        val titleLabel = JLabel(title)
        sectionPanel.add(titleLabel, BorderLayout.NORTH)

        val fileList = JList(listModel)
        fileList.selectionMode = ListSelectionModel.SINGLE_SELECTION

        fileList.addMouseListener(goToLineOnDoubleClick(project, fileList))

        val scrollPane = JBScrollPane(fileList)
        sectionPanel.add(scrollPane, BorderLayout.CENTER)

        val refreshButton = JButton("Refresh")
        refreshButton.addActionListener(refreshAction)

        sectionPanel.add(refreshButton, BorderLayout.SOUTH)

        return sectionPanel
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