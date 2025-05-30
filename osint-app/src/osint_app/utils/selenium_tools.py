from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from PIL import Image
import io

from typeguard import typechecked


@typechecked
def get_screenshot_and_element_by_class_name(driver: webdriver.Chrome, class_name: str) -> dict:
    WebDriverWait(driver, 30).until(
        EC.visibility_of_element_located((By.CLASS_NAME, class_name))
    )

    # Remove advertisement elements
    driver.execute_script("""
        var ele = document.getElementsByClassName('bsaStickyLeaderboard')[0];
        if (ele) { ele.parentNode.removeChild(ele); }
        var ele = document.getElementById('promo-outer');
        if (ele) { ele.parentNode.removeChild(ele); }
        var ele = document.getElementById('ctl00_divFooter');
        if (ele) { ele.parentNode.removeChild(ele); }
    """)

    # Wait for the page to load completely
    __import__("time").sleep(0.5)
    # Find the element containing the certificate chain information
    element = driver.find_element(By.CLASS_NAME, class_name)

    # Get the size of the element
    element_height = element.size['height']
    element_width = element.size['width']

    # Set window size to accommodate the element
    driver.set_window_size(max(1024, element_width + 100), max(768, element_height + 200))

    # Make sure element is in view
    driver.execute_script("arguments[0].scrollIntoView(true);", element)

    image_binary = element.screenshot_as_png
    img = Image.open(io.BytesIO(image_binary))

    return {
        "element": element,
        "image": img,
    }