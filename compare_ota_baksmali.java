// java -cp apktool.jar compare_ota_baksmali.java DEX OUTDIR: disassemble DEX with the baksmali in
// apktool.jar into one .smali file per class under OUTDIR, for compare-ota. The classes baksmali
// fails on are reported on stderr and skipped, which isn't an error: compare-ota disassembles them
// with dexdump instead.
import java.io.File;
import org.jf.baksmali.Baksmali;
import org.jf.baksmali.BaksmaliOptions;
import org.jf.dexlib2.DexFileFactory;

public class CompareOtaBaksmali {
    public static void main(String[] args) throws Exception {
        var container = DexFileFactory.loadDexContainer(new File(args[0]), null);
        for (String name : container.getDexEntryNames())
            Baksmali.disassembleDexFile(container.getEntry(name).getDexFile(), new File(args[1]), 1, new BaksmaliOptions());
    }
}
