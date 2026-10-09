"""verify_report: how verify prints its findings. Pure formatting, so every
input here is a sentence of the shape the checks in amap_sandy produce."""
import unittest

import verify_report as vr


class DisplayNamesTest(unittest.TestCase):
    def test_the_hash_is_dropped(self):
        self.assertEqual(vr.display_names(["lore-532efbb9", "OpenShell-88961355"]),
                         {"lore-532efbb9": "lore", "OpenShell-88961355": "OpenShell"})

    def test_a_name_two_sandboxes_share_keeps_both_hashes(self):
        got = vr.display_names(["pka-52be5033", "pka-0badcafe", "lore-532efbb9"])
        self.assertEqual(got["pka-52be5033"], "pka-52be5033")
        self.assertEqual(got["pka-0badcafe"], "pka-0badcafe")
        self.assertEqual(got["lore-532efbb9"], "lore")

    def test_a_name_without_a_hash_is_shown_as_it_is(self):
        self.assertEqual(vr.display_names(["archived"]), {"archived": "archived"})


class GroupTest(unittest.TestCase):
    SLUGS = ["alpha-1111aaaa", "bravo-2222bbbb", "pka-52be5033", "pka-skills-7f875983"]

    def test_the_same_sentence_about_two_sandboxes_is_one_row_naming_both(self):
        rows = vr.group([
            "alpha-1111aaaa: relay health is not checkable until it is relaunched",
            "bravo-2222bbbb: relay health is not checkable until it is relaunched",
        ], self.SLUGS)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].condition, "relay health is not checkable until it is relaunched")
        self.assertEqual(rows[0].slugs, ["alpha-1111aaaa", "bravo-2222bbbb"])

    def test_a_labelled_sentence_loses_its_slug_and_keeps_its_label(self):
        rows = vr.group(["relay not alive: alpha-1111aaaa: heartbeat has no usable pid"],
                        self.SLUGS)
        self.assertEqual(rows[0].condition, "relay not alive: heartbeat has no usable pid")
        self.assertEqual(rows[0].slugs, ["alpha-1111aaaa"])

    def test_a_detail_that_differs_per_sandbox_stays_its_own_row(self):
        rows = vr.group([
            "relay not alive: alpha-1111aaaa: heartbeat is 300s old",
            "relay not alive: bravo-2222bbbb: heartbeat is 900s old",
        ], self.SLUGS)
        self.assertEqual([r.condition for r in rows],
                         ["relay not alive: heartbeat is 300s old",
                          "relay not alive: heartbeat is 900s old"])

    def test_a_slug_in_a_path_is_templated_so_the_same_path_groups(self):
        rows = vr.group([
            "lane leaf absent: alpha-1111aaaa: /h/instances/alpha-1111aaaa/inbox/notices — x",
            "lane leaf absent: bravo-2222bbbb: /h/instances/bravo-2222bbbb/inbox/notices — x",
        ], self.SLUGS)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].condition,
                         "lane leaf absent: /h/instances/<slug>/inbox/notices — x")

    def test_a_slug_named_as_a_value_is_kept_verbatim(self):
        """A policy entry to edit must show the exact slug."""
        line = ("router config: cannot render: policy 'task_graph' names recipient "
                "instance(s) that are not enrolled: bravo-2222bbbb. Those entries do nothing")
        rows = vr.group([line], self.SLUGS)
        self.assertIn("bravo-2222bbbb", rows[0].condition)
        self.assertEqual(rows[0].slugs, ["bravo-2222bbbb"])

    def test_a_slug_that_prefixes_another_is_not_found_inside_it(self):
        rows = vr.group(["pka-skills-7f875983: not launched yet"], self.SLUGS)
        self.assertEqual(rows[0].slugs, ["pka-skills-7f875983"])

    def test_a_sentence_about_no_sandbox_or_several_is_its_own_row_verbatim(self):
        lines = ["payload drift: /h/payload/relay is missing",
                 "overlap: alpha-1111aaaa and bravo-2222bbbb share a pair"]
        rows = vr.group(lines, self.SLUGS)
        self.assertEqual([(r.condition, r.slugs) for r in rows],
                         [(lines[0], []), (lines[1], [])])

    def test_rows_keep_first_appearance_order(self):
        rows = vr.group(["b: x", "alpha-1111aaaa: second", "a: y"], self.SLUGS)
        self.assertEqual([r.condition for r in rows], ["b: x", "second", "a: y"])


class RenderTest(unittest.TestCase):
    NAMES = {f"ws{i:02d}-0000aa{i:02d}": f"ws{i:02d}" for i in range(12)}

    def test_more_than_eight_workspaces_collapse_to_a_count(self):
        row = vr.Row("not running", sorted(self.NAMES))
        text = "\n".join(vr.render("NOTES", [row], self.NAMES, width=200))
        self.assertIn("ws07", text)
        self.assertNotIn("ws08", text)
        self.assertIn("… 4 more (--all to list)", text)

    def test_eight_are_listed_in_full(self):
        row = vr.Row("not running", sorted(self.NAMES)[:vr.COLLAPSE_AFTER])
        text = "\n".join(vr.render("NOTES", [row], self.NAMES, width=200))
        self.assertIn("ws07", text)
        self.assertNotIn("more", text)

    def test_all_lists_every_workspace(self):
        row = vr.Row("not running", sorted(self.NAMES))
        text = "\n".join(vr.render("NOTES", [row], self.NAMES, width=200, show_all=True))
        self.assertIn("ws11", text)
        self.assertNotIn("more", text)

    def test_workspaces_are_shown_by_name_beside_their_condition(self):
        row = vr.Row("relay health is not checkable", ["ws03-0000aa03"])
        line = [l for l in vr.render("NOTES", [row], self.NAMES, width=200)
                if "relay health" in l][0]
        self.assertTrue(line.rstrip().endswith("ws03"), line)
        self.assertNotIn("0000aa03", line)

    def test_no_rows_says_none(self):
        self.assertEqual(vr.render("PROBLEMS", [], {}, width=100), ["PROBLEMS", "  (none)"])


class PartSummaryTest(unittest.TestCase):
    def test_a_settled_part_is_its_label_with_a_count_of_its_pieces(self):
        self.assertEqual(vr.part_summary("payload", "relay present; status present", True),
                         "payload (2 files)")
        self.assertEqual(vr.part_summary("manifest", "feature.json present", True), "manifest")

    def test_an_unsettled_part_is_printed_whole_by_the_caller(self):
        self.assertIsNone(vr.part_summary("payload", "relay present; would create x", False))


if __name__ == "__main__":
    unittest.main()
