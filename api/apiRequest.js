import querystring from 'querystring'
import axios from 'axios'

export async function apiRequest(url, data, headers) {
    try {
        const config = {
            method: data ? 'POST' : 'GET',
            url: url,
            data: querystring.stringify(data),
            headers: headers,
        }

        const response = await axios(config)
        return response.data
    } catch (error) {
        console.error('API request failed:', error)
        throw error // Przekazanie błędu do wyższej warstwy obsługi
    }
}
