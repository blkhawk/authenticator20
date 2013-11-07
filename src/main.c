#include <pebble.h>
	
#include "config.h"
#include "sha1.h"
	
// Truncate n decimal digits to 2^n for 6 digits
#define DIGITS_TRUNCATE 1000000
#define SHA1_SIZE 20
	
//storage keys
#define KEY_TZ_SETTING 42
	
static Window *main_window;
static Window *tz_window;
static TextLayer *label;
static TextLayer *token;
static TextLayer *ticker;
static int curToken = 0;
static int tZone = 0;
static bool changed = true;

static char gmt[7];

static TextLayer *TZzone;
static TextLayer *TZlabel;

char* itoa2(int valIN, int base){ // 2 in the morning hack
	static char buf2[32] = {0};
	int i = 30;
	int val = abs(valIN);

	for(; val && i ; --i, val /= base)
		buf2[i] = "0123456789abcdef"[val % base];
	if(valIN<0)
		buf2[i] = '-';
	else if(valIN>0)
		buf2[i] = '+';
	if(valIN == 0)
		return &buf2[i+1];
	return &buf2[i];
	
}

void tz_window_single_click_handler(ClickRecognizerRef recognizer, Window *window) {
	int button = click_recognizer_get_button_id(recognizer);
	switch(button) {
		case BUTTON_ID_UP:
		    if(tZone<24){
				tZone++;
		    }
			strcpy(gmt+3, itoa2(tZone,10));
			text_layer_set_text(TZzone, gmt);
			changed = true;
			break;
		case BUTTON_ID_DOWN:
		    if(tZone > (-24)){
				tZone--;
		    }
			strcpy(gmt+3, itoa2(tZone,10));
			text_layer_set_text(TZzone, gmt);
			changed = true;
			break;
	}
}

static void tz_window_config_provider(void *context) {
	window_single_click_subscribe(BUTTON_ID_UP, (ClickHandler)tz_window_single_click_handler);
	window_single_click_subscribe(BUTTON_ID_DOWN, (ClickHandler)tz_window_single_click_handler);
}

void tz_window_load(Window *window) {
	// Define some event handlers for clicks
	window_set_click_config_provider(window, (ClickConfigProvider) tz_window_config_provider);
	Layer *window_layer = window_get_root_layer(window);
	
	strcpy(gmt, "UTC");
	strcpy(gmt+3, itoa2(tZone,10));
	
	TZzone = text_layer_create(GRect(0,50,144,48));
	text_layer_set_text_color(TZzone, GColorWhite);
	text_layer_set_background_color(TZzone, GColorBlack);
	text_layer_set_font(TZzone, fonts_get_system_font(FONT_KEY_GOTHIC_28_BOLD));
	text_layer_set_text_alignment(TZzone, GTextAlignmentCenter);
	text_layer_set_text(TZzone, gmt);
	
	TZlabel = text_layer_create(GRect(0,5,144,48));
	text_layer_set_text_color(TZlabel, GColorWhite);
	text_layer_set_background_color(TZlabel, GColorBlack);
	text_layer_set_font(TZlabel, fonts_get_system_font(FONT_KEY_GOTHIC_24_BOLD));
	text_layer_set_text_alignment(TZlabel, GTextAlignmentCenter);
	text_layer_set_text(TZlabel, "Change Time Zone");
	
	// Add the child layer to the current window (font_window)
	layer_add_child(window_layer, text_layer_get_layer(TZzone));
	layer_add_child(window_layer, text_layer_get_layer(TZlabel));
}

void tz_window_unload(Window *window) {
	Layer *window_layer = window_get_root_layer(window);
	layer_remove_child_layers(window_layer);
	
	text_layer_destroy(TZzone);
	text_layer_destroy(TZlabel);
	//store TZ setting
	persist_write_int(KEY_TZ_SETTING,tZone + 24); // store as unsigned 
}

static void handle_second_tick(struct tm *tick_time, TimeUnits units_changed) {
	sha1nfo s;
	uint8_t ofs;
	uint32_t otp;
	
	char sha1_time[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	
	int curSeconds = tick_time->tm_sec;
	
	if(curSeconds == 0 || curSeconds == 30 || changed)
	{
		changed = false;
		// TOTP uses seconds since epoch in the upper half of an 8 byte payload
		// TOTP is HOTP with a time based payload
		// HOTP is HMAC with a truncation function to get a short decimal key
		uint32_t unix_time = time(NULL) + ((0-tZone)*3600);
		unix_time /= 30; // div by 30;
		
		sha1_time[4] = (unix_time >> 24) & 0xFF;
		sha1_time[5] = (unix_time >> 16) & 0xFF;
		sha1_time[6] = (unix_time >> 8) & 0xFF;
		sha1_time[7] = unix_time & 0xFF;
		
		// First get the HMAC hash of the time payload with the shared key
		sha1_initHmac(&s, otpkeys[curToken], otpsizes[curToken]);
		sha1_write(&s, sha1_time, 8);
		sha1_resultHmac(&s);
		
		// Then do the HOTP truncation.  HOTP pulls its result from a 31-bit byte
		// aligned window in the HMAC result, then lops off digits to the left
		// over 6 digits.
		ofs=s.state.b[SHA1_SIZE-1] & 0xf;
		otp = 0;
		otp = ((s.state.b[ofs] & 0x7f) << 24) |
			((s.state.b[ofs + 1] & 0xff) << 16) |
			((s.state.b[ofs + 2] & 0xff) << 8) |
			(s.state.b[ofs + 3] & 0xff);
		otp %= DIGITS_TRUNCATE;
		
		static char tokenText[] = "AABBCC";
		snprintf(tokenText, sizeof(tokenText), "%06lu", (unsigned long)otp);
		
		text_layer_set_text(label, otplabels[curToken]);
		text_layer_set_text(token, tokenText);
	}
	
	static char secondText[] = "00";
	snprintf(secondText, sizeof(secondText), "%02d", (30 - (curSeconds % 30)));
	text_layer_set_text(ticker, secondText);
}

void single_click_handler(ClickRecognizerRef recognizer, Window *window) {
	int button = click_recognizer_get_button_id(recognizer);
	switch(button) {
		case BUTTON_ID_SELECT:
			window_stack_push(tz_window, true);
			return;
			break;
		case BUTTON_ID_UP:
			if (curToken==0) {
				curToken=NUM_SECRETS-1;
			} else {
				curToken--;
			};
			changed = true;
			break;
		case BUTTON_ID_DOWN:
			if ((curToken+1)==NUM_SECRETS) {
				curToken=0;
			} else {
				curToken++;
			};
			changed = true;
			break;
	}
	time_t t = time(NULL);
	handle_second_tick(gmtime(&t),SECOND_UNIT);
}

static void main_window_config_provider(void *context) {
	window_single_click_subscribe(BUTTON_ID_UP, (ClickHandler)single_click_handler);
	window_single_click_subscribe(BUTTON_ID_SELECT, (ClickHandler)single_click_handler);
	window_single_click_subscribe(BUTTON_ID_DOWN, (ClickHandler)single_click_handler);
}

static void main_window_load(Window *window) {
	// Define some event handlers for clicks
	window_set_click_config_provider(window, (ClickConfigProvider) main_window_config_provider);
	Layer *window_layer = window_get_root_layer(window);
	// Init the identifier label
	label = text_layer_create(GRect(5, 30, 144-4, 168-44));
	text_layer_set_text_color(label, GColorWhite);
	text_layer_set_background_color(label, GColorClear);
	text_layer_set_font(label, fonts_get_system_font(FONT_KEY_GOTHIC_28_BOLD));

	// Init the token label
	token = text_layer_create(GRect(10, 60, 144-4 /* width */, 168-44 /* height */));
	text_layer_set_text_color(token, GColorWhite);
	text_layer_set_background_color(token, GColorClear);
	text_layer_set_font(token, fonts_get_system_font(FONT_KEY_BITHAM_34_MEDIUM_NUMBERS));

	// Init the second ticker
	ticker = text_layer_create(GRect(60, 120, 144-4 /* width */, 168-44 /* height */));
	text_layer_set_text_color(ticker, GColorWhite);
	text_layer_set_background_color(ticker, GColorClear);
	text_layer_set_font(ticker, fonts_get_system_font(FONT_KEY_GOTHIC_18_BOLD));
	
	// Add the child layer to the current window (font_window)
	layer_add_child(window_layer, text_layer_get_layer(label));
	layer_add_child(window_layer, text_layer_get_layer(token));
	layer_add_child(window_layer, text_layer_get_layer(ticker));

	tick_timer_service_subscribe(SECOND_UNIT, handle_second_tick);
}

static void main_window_unload(Window *window) {
	tick_timer_service_unsubscribe();
	
	Layer *window_layer = window_get_root_layer(window);
	layer_remove_child_layers(window_layer);
	
	text_layer_destroy(label);
	text_layer_destroy(token);
	text_layer_destroy(ticker);
}
	
static void init(void) {
	//load TZ settings / default TZ
	tZone = persist_exists(KEY_TZ_SETTING) ? (persist_read_int(KEY_TZ_SETTING)-24): DEFAULT_TIME_ZONE;
	changed = true;
	
	tz_window = window_create();
	WindowHandlers tz_window_handlers = {
	  .load = tz_window_load,
	  .unload = tz_window_unload
	};
	window_set_window_handlers(tz_window, tz_window_handlers);
	window_set_background_color(tz_window, GColorBlack);
	
	main_window = window_create();
	WindowHandlers main_window_handlers = {
	  .load = main_window_load,
	  .unload = main_window_unload
	};
	window_set_window_handlers(main_window, main_window_handlers);
	window_set_background_color(main_window, GColorBlack);
	window_stack_push(main_window, true /* Animated */);
	
	time_t t = time(NULL);
	handle_second_tick(gmtime(&t),SECOND_UNIT);
}

static void deinit(void) {
	window_destroy(main_window);
}

int main(void) {
  init();
  app_event_loop();
  deinit();

  return 0;
}