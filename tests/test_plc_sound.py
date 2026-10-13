"""Offline scan model executing the timing/output IL from the saved PLC project.

This validates the phase logic, not Schneider compilation or physical relay timing.
"""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


PROJECT = Path(__file__).resolve().parents[1] / "Seren_Alarm.smbp"


class SoundScanModel:
    def __init__(self, duration, pause, interval, count):
        project = ET.parse(PROJECT)
        rungs = project.findall(".//RungEntity")
        start = next(i for i, rung in enumerate(rungs)
                     if rung.findtext("Name") == "Generator_Enable")
        self.rungs = [[line.text for line in rung.findall(".//InstructionLine")]
                      for rung in rungs[start:]]
        self.values = dict.fromkeys(["%M10", "%M11", "%M12", "%M13", "%MW14"], 0)
        self.values.update({"%I0.0": True, "%MW10": count})
        bases = {"TenMilliSeconds": 10, "OneSecond": 1000}
        timers = {timer.findtext("Address"): timer for timer in project.findall(".//TimerTM")}
        self.presets = {address: (milliseconds // bases[timers[address].findtext("Base")])
                        * bases[timers[address].findtext("Base")]
                        for address, milliseconds in zip(("%TM1", "%TM2", "%TM3"),
                                                         (duration, pause, interval))}
        self.started = {}

    def scan(self, now):
        for rung in self.rungs:
            accumulator = False
            timer = None
            timer_q = False
            for line in rung:
                op, *args = line.split()
                operand = " ".join(args)
                if op == "BLK":
                    timer = operand
                elif op in ("LD", "LDN", "AND", "ANDN"):
                    if operand == "[ %MW14 >= %MW10 ]":
                        value = self.values["%MW14"] >= self.values["%MW10"]
                    elif operand == "[ %MW10 > 0 ]":
                        value = self.values["%MW10"] > 0
                    else:
                        value = timer_q if operand == "Q" else bool(self.values[operand])
                    if op.endswith("N"):
                        value = not value
                    accumulator = value if op.startswith("LD") else accumulator and value
                elif op == "IN":
                    if accumulator:
                        self.started.setdefault(timer, now)
                        timer_q = now - self.started[timer] >= self.presets[timer]
                    else:
                        self.started.pop(timer, None)
                        timer_q = False
                elif op == "ST":
                    self.values[operand] = accumulator
                elif op in ("S", "R"):
                    if accumulator:
                        self.values[operand] = op == "S"
                elif op == "[":
                    if accumulator:
                        if operand == "%MW14 := %MW14 + 1 ]":
                            self.values["%MW14"] += 1
                        elif operand == "%MW14 := 0 ]":
                            self.values["%MW14"] = 0
                        else:
                            raise AssertionError(line)
                elif op not in ("OUT_BLK", "END_BLK"):
                    raise AssertionError(line)
        return self.values["%Q0.0"]


class PLCSoundTests(unittest.TestCase):
    def test_output_ladder_and_il_agree_for_every_phase(self):
        import itertools
        for rung in ET.parse(PROJECT).findall(".//RungEntity"):
            if rung.findtext("Name") not in ("Output_Siren", "Output_Light"):
                continue
            for bits in itertools.product((False, True), repeat=5):
                values = dict(zip(("%I0.0", "%M10", "%M11", "%M12", "%M13"), bits))
                ladder = True
                for cell in rung.findall("./LadderElements/LadderEntity"):
                    kind = cell.findtext("ElementType")
                    if kind in ("NormalContact", "NegatedContact"):
                        value = values[cell.findtext("Descriptor")]
                        ladder = ladder and (not value if kind == "NegatedContact" else value)
                il = False
                for line in rung.findall(".//InstructionLine"):
                    op, address = line.text.split()
                    if op == "LD":
                        il = values[address]
                    elif op in ("AND", "ANDN"):
                        il = il and (not values[address] if op == "ANDN" else values[address])
                self.assertEqual(ladder, il, (rung.findtext("Name"), values))

    def test_beeps_follow_duration_not_pause_and_series_count(self):
        for duration, pause, count in ((500, 300, 3), (200, 400, 2), (1000, 0, 1), (10, 600, 1)):
            with self.subTest(duration=duration, pause=pause, count=count):
                model = SoundScanModel(duration, pause, 4000, count)
                edges = []
                previous = False
                for now in range(12000):
                    sounding = model.scan(now)
                    self.assertEqual(sounding, model.values["%Q0.1"])
                    if sounding != previous:
                        edges.append((now, sounding))
                    previous = sounding
                self.assertGreaterEqual(len(edges), 2 * (count + 1))
                for i in range(count):
                    self.assertLessEqual(abs(edges[2*i+1][0] - edges[2*i][0] - duration), 1)
                for i in range(count - 1):
                    self.assertLessEqual(abs(edges[2*i+2][0] - edges[2*i+1][0] - pause), 2)
                # Existing sequencing starts the series timer after the last within-series pause.
                gap = edges[2*count][0] - edges[2*count-1][0]
                self.assertLessEqual(abs(gap - (4000 + pause)), 2)

    def test_zero_beep_count_stops_active_series_with_other_presets_unchanged(self):
        model = SoundScanModel(1200, 400, 4000, 3)
        self.assertTrue(model.scan(0))
        model.values['%MW10'] = 0
        self.assertFalse(model.scan(500))
        self.assertFalse(any(model.scan(now) for now in range(501, 10000)))

    def test_switch_off_and_zero_presets_suppress_output(self):
        model = SoundScanModel(0, 0, 0, 0)
        self.assertFalse(any(model.scan(now) for now in range(50)))
        model = SoundScanModel(500, 300, 4000, 3)
        self.assertTrue(model.scan(0))
        model.values["%I0.0"] = False
        self.assertFalse(model.scan(1))
