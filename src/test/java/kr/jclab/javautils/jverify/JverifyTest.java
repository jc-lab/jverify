package kr.jclab.javautils.jverify;

import net.jsign.pe.PEFile;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class JverifyTest {
    Jverify jverify = new Jverify();

    @Test
    public void verify_correctSamplePy_shouldTrue() throws Exception {
        Path filePath = Files.createTempFile("tmp", ".exe");

        try (InputStream in = this.getClass().getResourceAsStream("/samples/py.exe")) {
            try (OutputStream out = Files.newOutputStream(filePath.toFile().toPath())) {
                IOUtils.copy(in, out);
            }
        }

        PEFile peFile = new PEFile(filePath.toFile());

        assertTrue(jverify.verify(peFile));
    }

    @Test
    public void verify_nonSignedSampleNotepad_shouldFalse() throws Exception {
        Path filePath = Files.createTempFile("tmp", ".exe");

        try (InputStream in = this.getClass().getResourceAsStream("/samples/notepad.exe")) {
            try (OutputStream out = Files.newOutputStream(filePath.toFile().toPath())) {
                IOUtils.copy(in, out);
            }
        }

        PEFile peFile = new PEFile(filePath.toFile());

        assertFalse(jverify.verify(peFile));
    }
}