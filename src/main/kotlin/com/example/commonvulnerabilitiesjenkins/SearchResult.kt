package com.example.commonvulnerabilitiesjenkins

import com.intellij.openapi.vfs.VirtualFile

class SearchResult(val file: VirtualFile?, val lineNumber: Int?, val offset: Int, val vuln: String?) {

    override fun toString(): String {
        return if (file == null || lineNumber == null) {
            "No result found"
        } else
            "${file.name} | Line ${lineNumber + 1} | ${vuln}"
    }
}