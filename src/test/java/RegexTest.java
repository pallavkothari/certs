import org.junit.Test;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RegexTest {
    // captures subdomain if present
    private static final String REGEX = "(.*\\.)[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}";
    private static final Pattern PATTERN = Pattern.compile(REGEX);

    @Test
    public void testStrippingSubdomain() {
        String test = "foo.google.com";
        Matcher matcher = PATTERN.matcher(test);
        assertTrue(matcher.matches());
        if (matcher.matches()) {
            String group = matcher.group(1);
            assertThat(group, is("foo."));
            assertThat(test.substring(group.indexOf(group) + group.length()), is("google.com"));
        }
    }

    @Test
    public void testNoSubdomain() {
        String test = "google.com";
        Matcher m = PATTERN.matcher(test);
        assertFalse(m.matches());
    }
}
