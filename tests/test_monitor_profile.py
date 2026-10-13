from dataclasses import asdict
import threading
import tkinter as tk
import unittest
from unittest.mock import patch
from src.channel_tuning import ChannelProfile
from src.channel_debug_model import analyze_messages,date_window
from src.threat_config_dialog import ThreatConfigDialog


class MonitorProfileRegression(unittest.TestCase):
    def setUp(self):
        self.profile=ChannelProfile('profiles/monitor1654')
        self.config=self.profile.load_config()
        self.config.schedule.enabled=False
        self.start,self.end=date_window('2026-10-05','2026-10-05')

    def message(self,id,seconds,text):
        return dict(id=f'monitor1654/{id}',channel='monitor1654',timestamp=self.start+seconds,text=text)

    def analyze(self,messages):
        with patch('urllib.request.urlopen',side_effect=AssertionError('No network in archive analysis')):
            return analyze_messages(messages,'monitor1654',self.start,self.end,self.config,threading.Event(),lambda s:None)

    def test_standalone_city_target_does_not_inherit_recent_drone(self):
        result=self.analyze([self.message(1,10,'Шахед на Лісне'),self.message(2,20,'Ціль на місто')])
        self.assertGreater(result.rows[-1]['levels']['rocket'],0)
        self.assertEqual(result.rows[-1]['event']['category'],'rocket')

    def test_standalone_above_city_is_critical_rocket(self):
        result=self.analyze([self.message(1,10,'Шахед на Лісне'),self.message(2,20,'Ціль над містом')])
        self.assertEqual(result.rows[-1]['event']['category'],'rocket')
        self.assertEqual(result.rows[-1]['levels']['rocket'],4)

    def test_reply_city_target_uses_referenced_bomb_not_latest_drone(self):
        reply=self.message(3,30,'Ціль над містом');reply['reply_to']='monitor1654/1'
        result=self.analyze([self.message(1,10,'Пуски КАБ'),self.message(2,20,'Шахед на Лісне'),reply])
        self.assertEqual(result.rows[-1]['event']['category'],'kab')
        self.assertEqual(result.rows[-1]['levels']['rocket'],0)

    def test_reply_quote_supplies_explicit_type_if_parent_not_loaded(self):
        reply=self.message(3,30,'Ціль над містом');reply.update(reply_to='monitor1654/999',reply_text='Ударний БПЛА на Лісне')
        result=self.analyze([reply])
        self.assertEqual(result.rows[-1]['event']['category'],'drone')
        self.assertEqual(result.rows[-1]['levels']['rocket'],0)

    def test_direction_above_city_and_apostrophe_variants(self):
        for apostrophe in ("'",'ʼ','’'):
            with self.subTest(apostrophe=apostrophe):
                result=self.analyze([self.message(1,10,'Ударний БПЛА на Лісне'),
                    self.message(2,20,f'Далі на П{apostrophe}ятихатки'),
                    self.message(3,30,f'Над П{apostrophe}ятихатками')])
                self.assertEqual([r['levels']['drone'] for r in result.rows],[1,1,2])

    def test_distant_launches_are_filtered_without_clearing_an_existing_city_threat(self):
        result=self.analyze([self.message(1,10,'Авіація заходить на пуски КАБ на Великий Бурлук'),
                            self.message(2,20,'КАБ над Харків'),
                            self.message(3,30,'Повторні пуски КАБ на Приколотне')])
        self.assertEqual(result.rows[0]['levels']['kab'],0)
        self.assertIn('Дальний',result.rows[0]['event']['outcome'])
        self.assertEqual(result.rows[2]['levels']['kab'],4)

    def test_region_and_toward_city_are_distinct_and_citywide_cancel_clears_groups(self):
        result=self.analyze([self.message(1,10,'КАБ на Вовчанський район'),
                            self.message(2,20,'Щонайменше 2 КАБи перетинають кордон в напрямку Козачої Лопані'),
                            self.message(3,30,'Відбій загрози')])
        self.assertEqual([r['levels']['kab'] for r in result.rows],[1,2,0])
        self.assertEqual(result.rows[0]['event']['proximity'],'Вне города')

    def test_pinned_forecast_is_visible_but_does_not_raise_alarm(self):
        result=self.analyze([self.message(1,10,'monitor pinned «Маємо ознаки підготовки масового ракетного удару, реагуйте на сигнали тривоги»')])
        self.assertEqual(result.rows[0]['level'],0)
        self.assertIn('Информационное',result.rows[0]['event']['outcome'])

    def test_prelaunch_and_direct_city_are_different_threat_stages(self):
        result=self.analyze([self.message(1,10,'Загроза пусків КАБ в напрямку Козачої Лопані'),
                            self.message(2,20,'КАБ продовжує рух на Тишки. Є загроза для міста'),
                            self.message(3,30,'4 КАБа на місто')])
        self.assertEqual([r['levels']['kab'] for r in result.rows],[1,2,4])
        self.assertFalse(result.rows[0]['event']['launch_detected'])
        self.assertIn('не подтверждён',result.rows[0]['event']['badge_target'])
        self.assertEqual(result.rows[2]['event']['direction'],'На город')
        self.assertNotEqual(result.rows[2]['event']['proximity'],'Над городом')

    def test_prelaunch_warning_does_not_expire_an_existing_confirmed_city_target(self):
        result=self.analyze([self.message(1,10,'КАБ на місто'),
                            self.message(2,20,'Загроза пусків КАБ в напрямку Козачої Лопані'),
                            self.message(3,100,'Інформація')])
        self.assertEqual(result.rows[2]['levels']['kab'],4)

    def test_channel_editor_preserves_filters_and_explicit_global_cancel(self):
        root=tk.Tk();root.withdraw();saved=[]
        dialog=ThreatConfigDialog(root,self.config,saved.append,persist=False,channel_only=True)
        dialog.withdraw()
        try:
            titles=[dialog.notebook.tab(t,'text') for t in dialog.notebook.tabs()]
            self.assertNotIn('Звуковые профили',titles)
            self.assertNotIn('Биты ПЛК',titles)
            with patch('src.threat_config_dialog.messagebox.showinfo'),patch('src.threat_config_dialog.messagebox.showerror') as errors:
                dialog._save_and_close()
                self.assertFalse(errors.called,errors.call_args)
            self.assertEqual(saved[0].district.ignored_location_keywords,self.config.district.ignored_location_keywords)
            self.assertEqual(saved[0].district.regional_keywords,self.config.district.regional_keywords)
            self.assertTrue(saved[0].end_conditions[0].global_without_location)
            compound=next(c for c in saved[0].end_conditions if c.allow_continuing)
            original=next(c for c in self.config.end_conditions if c.allow_continuing)
            self.assertTrue(compound.require_context_type)
            self.assertEqual(compound.required_keywords,original.required_keywords)
            self.assertEqual(saved[0].tracking.regional_city_direction_keywords,self.config.tracking.regional_city_direction_keywords)
            self.assertEqual(saved[0].district.urban_keywords,self.config.district.urban_keywords)
            self.assertEqual(saved[0].tracking.generic_target_keywords,self.config.tracking.generic_target_keywords)
            self.assertEqual(saved[0].tracking.generic_target_type,'rocket')
            self.assertFalse(saved[0].alarmmap_enabled)
            for rule in saved[0].alarm_rules:
                self.assertNotIn('alarmmap',rule.sources)
                self.assertEqual(rule.api_types,[])
        finally:
            if dialog.winfo_exists():dialog.destroy()
            root.destroy()

    def test_banderol_is_rocket_and_followup_does_not_become_drone(self):
        result=self.analyze([self.message(1,10,'Бандероль на Рогань'),
                            self.message(2,20,'Далі на Індустріальний р-н'),
                            self.message(3,30,'Впала'),
                            self.message(4,200,'Бандероль на Рогань')])
        self.assertEqual([r['levels']['rocket'] for r in result.rows],[1,2,2,1])
        self.assertTrue(all(r['levels']['drone']==0 for r in result.rows))

    def test_fast_target_and_inner_city_location(self):
        result=self.analyze([self.message(1,10,'Швидкісна на місто'),
                            self.message(2,20,'на МІСТО')])
        self.assertEqual([r['levels']['rocket'] for r in result.rows],[2,2])
        result=self.analyze([self.message(1,10,'Ударний на Лісне'),
                            self.message(2,20,'на просп. Перемоги')])
        self.assertEqual([r['levels']['drone'] for r in result.rows],[1,2])

    def test_suburb_and_confirmed_direction_and_preparation_are_distinct(self):
        result=self.analyze([self.message(1,10,'Заходять на пуски КАБ по Козачій Лопані'),
                            self.message(2,20,'КАБ на Козачу Лопань'),
                            self.message(3,30,'2 КАБи перетинають кордон в напрямку Козачої Лопані')])
        self.assertEqual([r['levels']['kab'] for r in result.rows],[0,1,2])

    def test_plural_cab_landing_preserves_independent_drone_and_requires_cab_context(self):
        result=self.analyze([self.message(1,10,'Шахед над Харків'),
                            self.message(2,20,'2 КАБи перетинають кордон в напрямку Козачої Лопані'),
                            self.message(3,30,'Впали в області. Без повторних пусків')])
        self.assertEqual(result.rows[-1]['levels']['kab'],0)
        self.assertEqual(result.rows[-1]['levels']['drone'],2)
        result=self.analyze([self.message(1,10,'2 КАБи перетинають кордон в напрямку Козачої Лопані'),
                            self.message(2,20,'2 Шахеди над Харків'),
                            self.message(3,30,'Впали в області')])
        self.assertEqual(result.rows[-1]['levels']['kab'],2)

    def test_old_saltiv_is_distinct_from_city_saltivka(self):
        for remote in ('Швидкісна на Старий Салтів', 'Швидкісна на Старый Салтов'):
            result=self.analyze([self.message(1,10,remote)])
            self.assertEqual(result.rows[0]['levels']['rocket'],0)
            self.assertIn('Дальний',result.rows[0]['event']['outcome'])
        result=self.analyze([self.message(1,10,'Швидкісна на Салтівку')])
        self.assertEqual(result.rows[0]['levels']['rocket'],1)

    def test_remote_city_shelter_context_does_not_raise_kharkiv_alarm(self):
        result=self.analyze([self.message(1,10,'Бандероль на Чугуїв'),
                            self.message(2,20,'Місто переходьте в укриття'),
                            self.message(3,30,'Харків переходьте в укриття')])
        self.assertEqual(result.rows[1]['level'],0)
        self.assertIn('другого населённого пункта',result.rows[1]['event']['outcome'])
        self.assertGreater(result.rows[2]['level'],0)
        result=self.analyze([self.message(1,10,'Шахед над Харків'),
                            self.message(2,20,'Бандероль на Чугуїв'),
                            self.message(3,30,'Місто переходьте в укриття')])
        self.assertEqual(result.rows[-1]['levels']['drone'],2)
        self.assertEqual(result.rows[-1]['levels']['rocket'],0)

    def test_cab_direction_alone_does_not_imply_confirmed_border_crossing(self):
        result=self.analyze([self.message(1,10,'КАБ в напрямку Козачої Лопані'),
                            self.message(2,20,'2 КАБи перетинають кордон в напрямку Козачої Лопані'),
                            self.message(3,30,'Впав. Заходять на повторні пуски'),
                            self.message(4,40,'КАБ в напрямку Козачої Лопані')])
        self.assertEqual([r['levels']['kab'] for r in result.rows],[1,2,0,1])

    def test_group_ending_requires_both_fall_and_new_series_markers(self):
        for ending in ('Впав', 'Заходять на повторні пуски', 'Не впав. Заходять на повторні пуски'):
            result=self.analyze([self.message(1,10,'2 КАБи перетинають кордон в напрямку Козачої Лопані'),
                                self.message(2,20,ending)])
            self.assertEqual(result.rows[-1]['levels']['kab'],2)

    def test_fpvs_and_unknown_bplas_have_different_city_levels(self):
        result=self.analyze([self.message(1,10,'FPV над Великою Данилівкою')])
        self.assertEqual(result.rows[0]['levels']['drone'],1)
        result=self.analyze([self.message(1,10,'БПЛА невизначеного типу на Аеропорт'),
                            self.message(2,20,'Знов фіксується курсом на Малишева')])
        self.assertEqual([r['levels']['drone'] for r in result.rows],[2,2])
        result=self.analyze([self.message(1,10,'Реактивний Шахед на Основу')])
        self.assertEqual(result.rows[0]['levels']['drone'],4)

    def test_city_landmarks_and_departure_replace_only_confirmed_previous_position(self):
        result=self.analyze([self.message(1,10,'Реактивний Шахед на Масельського'),
                            self.message(2,20,'Реактивний Шахед на невідомий орієнтир'),
                            self.message(3,30,'Реактивний Шахед на Хроли/Індустріальний район'),
                            self.message(4,40,'Реактивний Шахед вилетів з міста на Південне/Люботин')])
        self.assertEqual([r['levels']['drone'] for r in result.rows],[4,4,2,1])

    def test_loss_of_fix_with_known_new_position_does_not_keep_old_district_level(self):
        result=self.analyze([self.message(1,10,'Ударний на Безлюдівку'),
                            self.message(2,20,'Далі на Мерефу'),
                            self.message(3,30,'Далі на Високий. Більше не фіксується')])
        self.assertEqual([r['levels']['drone'] for r in result.rows],[4,4,1])

    def test_confirmed_drone_destruction_preserves_cab(self):
        result=self.analyze([self.message(1,10,'КАБ на місто'),
                            self.message(2,20,'Шахед над Харків'),
                            self.message(3,30,'Збиття в небі')])
        self.assertEqual(result.rows[-1]['levels']['drone'],0)
        self.assertEqual(result.rows[-1]['levels']['kab'],4)

    def test_ended_cab_context_is_not_used_for_new_untyped_target(self):
        result=self.analyze([self.message(1,10,'2 КАБи перетинають кордон в напрямку Козачої Лопані'),
                            self.message(2,20,'Впав. На даний час без повторних пусків'),
                            self.message(3,30,'Ціль на Дергачі')])
        self.assertEqual(result.rows[-1]['levels']['kab'],0)
        self.assertEqual(result.rows[-1]['levels']['rocket'],1)
        self.assertEqual(result.rows[-1]['levels']['drone'],0)
        result=self.analyze([self.message(1,10,'КАБ на місто'),
                            self.message(2,20,'Ціль на Дергачі')])
        self.assertEqual(result.rows[-1]['levels']['drone'],0)
        result=self.analyze([self.message(1,10,'КАБ на місто'),
                            self.message(2,700,'Ціль на Дергачі')])
        self.assertEqual(result.rows[-1]['levels']['kab'],0)
        self.assertEqual(result.rows[-1]['levels']['rocket'],1)
        self.assertEqual(result.rows[-1]['levels']['drone'],0)

    def test_route_continues_after_gap_but_multiple_explicit_types_remain_ambiguous(self):
        result=self.analyze([self.message(1,10,'Ударний на Козачу Лопань'),
                            self.message(2,1434,'Далі на Слатине'),
                            self.message(3,1590,'Далі на Дергачі')])
        self.assertEqual(result.rows[-1]['levels']['drone'],1)
        result=self.analyze([self.message(1,10,'КАБ і ракета над Харків'),
                            self.message(2,20,'Далі на Основу')])
        self.assertEqual(result.rows[-1]['levels']['drone'],0)

    def test_bunker_advertisement_does_not_inherit_recent_cab_context(self):
        result=self.analyze([self.message(1,10,'КАБ на Мартове'),
                            self.message(2,20,"Харків'яни! Bunker Bar — доставка по всьому місту, бронювання столиків")])
        self.assertEqual(result.rows[-1]['levels']['kab'],0)
        self.assertIn('Информационное',result.rows[-1]['event']['outcome'])

    def test_citywide_all_clear_is_not_blocked_by_remote_geographic_context(self):
        result=self.analyze([self.message(1,10,'КАБ на місто'),
                            self.message(2,20,'КАБ на Великий Бурлук'),
                            self.message(3,30,'Відбій для міста')])
        self.assertEqual(result.rows[-1]['levels']['kab'],0)
        self.assertIn('сняты',result.rows[-1]['event']['outcome'])

    def test_ballistics_and_banderol_warnings_are_low_rocket_not_drone(self):
        for text in ('Загроза балістики з Курська','Загроза балістики з Ліски',
                     'Балістика з Курська','Загроза пусків ракети «Бандероль»'):
            result=self.analyze([self.message(1,10,text)])
            self.assertEqual(result.rows[0]['levels']['rocket'],1)
            self.assertEqual(result.rows[0]['levels']['drone'],0)

    def test_course_wording_still_means_confirmed_border_crossing(self):
        result=self.analyze([self.message(1,10,'КАБ курсом на Козачу Лопань'),
                            self.message(2,20,'перетинає кордон курсом на Козачу Лопань')])
        self.assertEqual([r['levels']['kab'] for r in result.rows],[1,2])

    def test_plural_cab_landing_finishes_group_without_clearing_drones(self):
        result=self.analyze([self.message(1,10,'Шахед над Харків'),
                            self.message(2,20,'2 КАБ на Салтівку/Немишлю'),
                            self.message(3,30,'2 КАБ на Ювілейний проспект'),
                            self.message(4,40,'Впали')])
        self.assertEqual(result.rows[1]['levels']['kab'],4)
        self.assertEqual(result.rows[-1]['levels']['kab'],0)
        self.assertEqual(result.rows[-1]['levels']['drone'],2)

    def test_repeated_position_does_not_leave_an_orphan_high_rocket_record(self):
        result=self.analyze([self.message(1,10,'Швидкісна на місто'),
                            self.message(2,20,'В УКРИТТЯ'),
                            self.message(3,30,'На Сокільники'),
                            self.message(4,40,'Далі на Подвірки')])
        self.assertEqual([r['levels']['rocket'] for r in result.rows],[2,4,2,1])

    def test_new_untyped_city_target_uses_rocket_after_expired_drone_context(self):
        result=self.analyze([self.message(1,10,'Ланцет на Руські Тишки'),
                            self.message(2,1100,'Ціль на Олексіївку')])
        self.assertEqual(result.rows[-1]['levels']['rocket'],2)
        self.assertEqual(result.rows[-1]['levels']['drone'],0)

        result=self.analyze([self.message(1,10,'Шахед на Лісне'),
                            self.message(2,20,'Ціль на Дергачі')])
        self.assertEqual(result.rows[-1]['levels']['drone'],1)
        self.assertEqual(result.rows[-1]['levels']['rocket'],0)

    def test_explicit_rocket_report_and_shelter_use_new_levels(self):
        result=self.analyze([self.message(1,10,'Ракета!!!'),
                            self.message(2,20,'Ціль на місто'),
                            self.message(3,30,'В УКРИТТЯ')])
        self.assertEqual([r['levels']['rocket'] for r in result.rows],[2,4,4])
        self.assertEqual(result.rows[0]['event']['proximity'],'Не определено')

    def test_untyped_city_warning_uses_configured_rocket_default_without_invented_context(self):
        result=self.analyze([self.message(1,10,'на МІСТО')])
        self.assertEqual(result.rows[0]['levels']['rocket'],2)
        self.assertIn('тип по умолчанию профиля',result.rows[0]['reason'])
        self.assertNotIn('тип из контекста',result.rows[0]['reason'])
        result=self.analyze([self.message(1,10,'В УКРИТТЯ')])
        self.assertEqual(result.rows[0]['levels']['rocket'],4)
